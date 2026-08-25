"""Flask controllers for the local Log Center diagnostic index."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


class DiagnosticRouteController:
    def __init__(self, *, module: Any, store: Any) -> None:
        self.module = module
        self.store = store

    def _body(self) -> Mapping[str, Any]:
        value = self.module.request.get_json(silent=True)
        return value if isinstance(value, Mapping) else {}

    @staticmethod
    def _failure(code: str) -> dict[str, str]:
        # Do not echo SQLite paths, keys, SQL, or exception text through a
        # public route. The detailed cause belongs in local process diagnostics.
        return {"error_code": code, "technical_summary": "日志中心内部错误，未返回底层详情"}

    def search(self):
        try:
            return self.module.jsonify(ok=True, results=self.store.search(self._body()))
        except Exception as exc:
            return self.module.jsonify(ok=False, error="读取日志中心失败", failure=self._failure("diagnostics_search")), 503

    def incident(self, incident_id: str):
        try:
            value = self.store.incident(incident_id)
        except Exception as exc:
            return self.module.jsonify(ok=False, error="读取日志详情失败", failure=self._failure("diagnostics_incident")), 503
        if value is None:
            return self.module.jsonify(ok=False, error="日志 ID 不存在或已删除"), 404
        return self.module.jsonify(ok=True, incident=value)

    def export(self):
        body = self._body()
        raw_ids = body.get("incident_ids")
        if isinstance(raw_ids, str):
            raw_ids = [raw_ids]
        if not isinstance(raw_ids, list) or not raw_ids:
            return self.module.jsonify(ok=False, error="请选择至少一条日志"), 400
        fmt = str(body.get("format") or "json").strip().lower()
        if fmt not in {"json", "markdown"}:
            return self.module.jsonify(ok=False, error="导出格式无效"), 400
        try:
            content = self.store.export([str(value or "") for value in raw_ids], fmt)
        except Exception as exc:
            return self.module.jsonify(ok=False, error="导出日志失败", failure=self._failure("diagnostics_export")), 503
        return self.module.jsonify(ok=True, format=fmt, content=content, redaction_applied=True)

    def delete(self):
        body = self._body()
        raw_ids = body.get("incident_ids")
        if isinstance(raw_ids, str):
            raw_ids = [raw_ids]
        if not isinstance(raw_ids, list) or not raw_ids:
            return self.module.jsonify(ok=False, error="请选择要删除的日志"), 400
        try:
            deleted = self.store.delete([str(value or "") for value in raw_ids])
        except Exception as exc:
            return self.module.jsonify(ok=False, error="删除日志失败", failure=self._failure("diagnostics_delete")), 503
        return self.module.jsonify(ok=True, deleted=deleted)

    def clear_all(self):
        try:
            deleted = self.store.clear()
        except Exception as exc:
            return self.module.jsonify(ok=False, error="清空日志失败", failure=self._failure("diagnostics_clear_all")), 503
        return self.module.jsonify(ok=True, deleted=deleted)

    def health(self):
        try:
            return self.module.jsonify(ok=True, health=self.store.health())
        except Exception as exc:
            return self.module.jsonify(ok=False, error="读取日志中心状态失败", failure=self._failure("diagnostics_health")), 503


__all__ = ["DiagnosticRouteController"]
