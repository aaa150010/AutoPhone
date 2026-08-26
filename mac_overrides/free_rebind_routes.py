"""HTTP routes for the separate Free email-rebind workspace."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

try:
    from .free_mailbox_code import fetch_latest_code
    from .mailbox_otp_service import DEFAULT_FREE_MAILBOX_PROXY
except ImportError:  # pragma: no cover
    from free_mailbox_code import fetch_latest_code  # type: ignore[no-redef]
    from mailbox_otp_service import DEFAULT_FREE_MAILBOX_PROXY  # type: ignore[no-redef]


class FreeRebindRouteController:
    def __init__(self, *, module: Any, service: Any, error_response: Any) -> None:
        self.module = module
        self.service = service
        self.error_response = error_response

    def _unavailable(self):
        return self.module.jsonify(ok=False, error="Free 换绑服务尚未初始化"), 503

    def _body(self) -> Mapping[str, Any] | None:
        data = self.module.request.get_json(silent=True) or {}
        return data if isinstance(data, Mapping) else None

    def _mailbox_proxy(self) -> str:
        try:
            config = self.service._config() if callable(getattr(self.service, "_config", None)) else {}
        except Exception:
            config = {}
        if not isinstance(config, Mapping) or str(config.get("mailbox_network_mode") or "local_proxy").strip().lower() != "local_proxy":
            return ""
        return str(config.get("mailbox_proxy_url") or DEFAULT_FREE_MAILBOX_PROXY).strip()

    @staticmethod
    def _latest_code_status(exc: Exception) -> int:
        if isinstance(exc, ValueError) or getattr(exc, "retryable", None) is False:
            return 400
        return 502

    def state(self):
        if self.service is None:
            return self._unavailable()
        try:
            return self.module.jsonify(ok=True, **self.service.public_state())
        except Exception as exc:
            return self.error_response(exc, default_code="free_rebind_state", default_label="读取换绑状态", status=503)

    def mailboxes(self):
        if self.service is None:
            return self._unavailable()
        try:
            return self.module.jsonify(ok=True, pool="free_rebind", rows=self.service.pool.public_rows())
        except Exception as exc:
            return self.error_response(exc, default_code="free_rebind_pool_read", default_label="读取换绑邮箱池", status=503)

    def import_mailboxes(self):
        if self.service is None:
            return self._unavailable()
        data = self._body()
        if data is None:
            return self.error_response(ValueError("请求必须是 JSON 对象"), default_code="free_rebind_pool", default_label="换绑邮箱池")
        try:
            imported, skipped = self.service.import_mailboxes(str(data.get("pool_content") or ""))
            return self.module.jsonify(ok=True, imported=imported, skipped=skipped, rows=self.service.pool.public_rows())
        except Exception as exc:
            return self.error_response(exc, default_code="free_rebind_pool", default_label="换绑邮箱池")

    def mailbox_latest_code(self):
        if self.service is None:
            return self._unavailable()
        data = self._body()
        row_id = str(data.get("row_id") or "").strip() if data is not None else ""
        try:
            row = self.service.pool.entry(row_id)
            if row is None:
                raise ValueError("换绑邮箱行不存在")
            return self.module.jsonify(**fetch_latest_code(row.mailbox_url, proxy=self._mailbox_proxy()))
        except Exception as exc:
            return self.error_response(exc, default_code="free_rebind_latest_code", default_label="读取换绑邮箱验证码", status=self._latest_code_status(exc))

    def mailbox_url(self):
        if self.service is None:
            return self._unavailable()
        data = self._body()
        row_id = str(data.get("row_id") or "").strip() if data is not None else ""
        try:
            row = self.service.pool.entry(row_id)
            if row is None:
                raise ValueError("换绑邮箱行不存在")
            return self.module.jsonify(ok=True, mailbox_url=row.mailbox_url)
        except Exception as exc:
            return self.error_response(exc, default_code="free_rebind_mailbox_url", default_label="读取换绑取件地址")

    def delete_mailboxes(self):
        if self.service is None:
            return self._unavailable()
        data = self._body()
        row_ids = data.get("row_ids") if data is not None else None
        if not isinstance(row_ids, list):
            return self.error_response(ValueError("请选择要删除的换绑邮箱"), default_code="free_rebind_pool_delete", default_label="删除换绑邮箱")
        try:
            deleted = self.service.delete_mailboxes([str(value or "") for value in row_ids])
            return self.module.jsonify(ok=True, deleted=deleted, rows=self.service.pool.public_rows())
        except Exception as exc:
            return self.error_response(exc, default_code="free_rebind_pool_delete", default_label="删除换绑邮箱")

    def mailbox_status(self, status: str):
        if self.service is None:
            return self._unavailable()
        data = self._body()
        row_ids = data.get("row_ids") if data is not None else None
        if not isinstance(row_ids, list):
            return self.error_response(ValueError("请选择换绑邮箱"), default_code="free_rebind_pool_status", default_label="更新换绑邮箱状态")
        try:
            updated = self.service.set_mailbox_status([str(value or "") for value in row_ids], status)
            return self.module.jsonify(ok=True, updated=updated, rows=self.service.pool.public_rows())
        except Exception as exc:
            return self.error_response(exc, default_code="free_rebind_pool_status", default_label="更新换绑邮箱状态")

    def start(self):
        if self.service is None:
            return self._unavailable()
        data = self._body()
        if data is None:
            return self.error_response(ValueError("请求必须是 JSON 对象"), default_code="free_rebind_start", default_label="启动邮箱换绑")
        try:
            task = self.service.start(str(data.get("source_row_id") or ""), str(data.get("target_row_id") or ""))
            return self.module.jsonify(ok=True, task=task, state=self.service.public_state())
        except Exception as exc:
            return self.error_response(exc, default_code="free_rebind_start", default_label="启动邮箱换绑")

    def retry(self):
        if self.service is None:
            return self._unavailable()
        data = self._body()
        if data is None:
            return self.error_response(ValueError("请求必须是 JSON 对象"), default_code="free_rebind_retry", default_label="重试邮箱换绑")
        try:
            task = self.service.retry(str(data.get("task_id") or ""))
            return self.module.jsonify(ok=True, task=task, state=self.service.public_state())
        except Exception as exc:
            return self.error_response(exc, default_code="free_rebind_retry", default_label="重试邮箱换绑")

    def stop(self):
        if self.service is None:
            return self._unavailable()
        try:
            self.service.stop()
            return self.module.jsonify(ok=True, state=self.service.public_state())
        except Exception as exc:
            return self.error_response(exc, default_code="free_rebind_stop", default_label="停止邮箱换绑")


__all__ = ["FreeRebindRouteController"]
