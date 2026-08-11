"""Local configuration route handlers with credential-safe failures."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

try:
    from .route_failures import explicit_failure_payload
except ImportError:  # Loaded as a top-level runtime override.
    from route_failures import explicit_failure_payload  # type: ignore[no-redef]


class LocalConfigRouteController:
    def __init__(
        self,
        *,
        module: Any,
        context: Any,
        importer: Any,
        settings: Callable[[], Any],
        public_state: Callable[[], Any],
        busy_response: Callable[[], Any],
    ) -> None:
        self.module = module
        self.context = context
        self.importer = importer
        self.settings = settings
        self.public_state = public_state
        self.busy_response = busy_response

    def get(self):
        return self.module.jsonify(
            ok=True,
            config=self.context.masked_local_config(self.context.read_local_config()),
        )

    def export(self):
        try:
            data = self.module.request.get_json(silent=True) or {}
            download = bool(data.pop("download", False)) if isinstance(data, dict) else False
            config = dict(self.context.local_config_from_runtime(data, self.context.read_local_config()))
            if isinstance(config.get("nv_import"), Mapping):
                nv_import = dict(config["nv_import"])
                nv_import.pop("api_key", None)
                config["nv_import"] = nv_import
            visible = config if download else self.context.masked_local_config(config)
            return self.module.jsonify(ok=True, config=visible)
        except Exception as exc:
            return self._failure("local_config_export", "导出本地配置", exc)

    def import_config(self):
        if not self.context.lifecycle_lock.acquire(blocking=False):
            return self.busy_response()
        try:
            if self.importer.status(self.settings()).get("running"):
                return self.module.jsonify(
                    ok=False,
                    error="任务运行中，停止后才能导入配置",
                    state=self.public_state(),
                ), 409
            data = self.module.request.get_json(silent=True) or {}
            config = data.get("config") if isinstance(data, dict) else {}
            if not isinstance(config, dict):
                return self.module.jsonify(ok=False, error="配置 JSON 必须是对象"), 400
            config = self.context.write_local_config(
                self.context.local_config_from_runtime(config, self.context.read_local_config())
            )
            return self.module.jsonify(ok=True, config=self.context.masked_local_config(config))
        except Exception as exc:
            return self._failure("local_config_import", "导入本地配置", exc)
        finally:
            self.context.lifecycle_lock.release()

    def secret(self):
        try:
            data = self.module.request.get_json(silent=True) or {}
            value = self.context.local_config_secret(data.get("id") if isinstance(data, dict) else "")
            if not value:
                return self.module.jsonify(ok=False, error="本地配置没有保存这个密钥"), 404
            return self.module.jsonify(ok=True, value=value)
        except Exception as exc:
            return self._failure("local_config_secret", "读取本地密钥", exc)

    def _failure(self, node_code: str, node_label: str, exc: Exception):
        payload = explicit_failure_payload(
            node_code=node_code,
            node_label=node_label,
            error_code=f"{node_code}_failed",
            cause=f"{node_label}存储操作异常（{type(exc).__name__}）",
            http_status=500,
        )
        return self.module.jsonify(payload), 500


__all__ = ["LocalConfigRouteController"]
