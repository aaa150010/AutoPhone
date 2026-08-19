"""Save the isolated Free configuration and pending proxy draft together."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def save_free_config_bundle(
    config_store: Any,
    manager: Any,
    data: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate first, then persist the Free config and optional proxy draft."""
    normalized = config_store.normalize(data, previous=config_store.load())
    proxy_content = str(data.get("proxy_content") or "")
    proxy_imported = 0
    if proxy_content.strip():
        importer = getattr(getattr(manager, "proxies", None), "import_text", None)
        if not callable(importer):
            raise ValueError("Free 代理池尚未初始化")
        try:
            proxy_imported = int(importer(
                proxy_content,
                country=str(data.get("proxy_country") or "").strip().upper() or None,
                group=str(data.get("proxy_group") or "").strip() or None,
                scheme=str(
                    data.get("proxy_scheme")
                    or normalized.get("proxy_default_scheme")
                    or "http"
                ).strip().lower() or None,
            ))
        except TypeError:
            proxy_imported = int(importer(proxy_content))
    config_store.save(normalized)
    payload: dict[str, Any] = {
        "config": config_store.public(),
        "proxy_imported": proxy_imported,
    }
    # The Free page has one unified save action. Return the persisted pool on
    # every save so changing only the driver or Roxy workspace cannot make the
    # already-saved proxy table disappear from the page.
    public_proxies = getattr(getattr(manager, "proxies", None), "public", None)
    if callable(public_proxies):
        payload["proxies"] = public_proxies()
    return payload


class FreeControlRouteController:
    """HTTP mutations for isolated Free configuration and task history."""

    def __init__(
        self,
        *,
        module: Any,
        manager: Any,
        config_store: Any,
        state: Any,
        config_public: Any,
        failure_response: Any,
        request_lock: Any,
    ) -> None:
        self.module = module
        self.manager = manager
        self.config_store = config_store
        self.state = state
        self.config_public = config_public
        self.failure_response = failure_response
        self.request_lock = request_lock

    def config(self):
        if self.module.request.method == "GET":
            return self.module.jsonify(ok=True, config=self.config_public(), state=self.state())
        data = self.module.request.get_json(silent=True) or {}
        if not isinstance(data, Mapping):
            return self.failure_response(ValueError("配置必须是 JSON 对象"), default_code="free_config", default_label="保存 Free 配置")
        if self.manager is None or self.config_store is None or not self.request_lock.acquire(blocking=False):
            return self.module.jsonify(ok=False, error="Free 配置请求正在处理中", state=self.state()), 409
        try:
            if self.manager.public_state().get("running"):
                return self.module.jsonify(ok=False, error="Free 任务运行中，停止后才能修改配置", state=self.state()), 409
            payload = save_free_config_bundle(self.config_store, self.manager, data)
            return self.module.jsonify(ok=True, state=self.state(), **payload)
        except Exception as exc:
            return self.failure_response(exc, default_code="free_config", default_label="保存 Free 配置")
        finally:
            self.request_lock.release()

    def delete_tasks(self):
        if self.manager is None:
            return self.module.jsonify(ok=False, error="Free 注册服务尚未初始化"), 503
        data = self.module.request.get_json(silent=True) or {}
        if not isinstance(data, Mapping) or not isinstance(data.get("task_ids"), list):
            return self.failure_response(ValueError("请选择要删除的 Free 任务"), default_code="free_task_delete", default_label="删除 Free 任务记录")
        try:
            deleted = self.manager.delete_tasks([str(value or "") for value in data["task_ids"]])
            return self.module.jsonify(ok=True, deleted=deleted, state=self.state())
        except Exception as exc:
            return self.failure_response(exc, default_code="free_task_delete", default_label="删除 Free 任务记录")


__all__ = ["FreeControlRouteController", "save_free_config_bundle"]
