"""Free account actions kept outside the oversized main route module."""

from __future__ import annotations

from typing import Any, Callable, Mapping

try:
    from .free_register_common import FreeRegisterError
except ImportError:
    from free_register_common import FreeRegisterError  # type: ignore[no-redef]


class FreeAccountRouteController:
    def __init__(
        self,
        *,
        module: Any,
        manager: Any,
        config_store: Any,
        free_state: Callable[[], Mapping[str, Any]],
        error_response: Callable[..., Any],
    ) -> None:
        self.module = module
        self.manager = manager
        self.config_store = config_store
        self.free_state = free_state
        self.error_response = error_response

    def _unavailable(self):
        return self.module.jsonify(ok=False, error="Free 注册服务尚未初始化"), 503

    def _live_service(self) -> Any:
        service = getattr(self.manager, "live_checks", None) if self.manager is not None else None
        if service is None:
            raise FreeRegisterError(
                "free_live_unavailable",
                "Free 账号测活",
                "Free 账号测活服务尚未初始化",
                retryable=True,
            )
        return service

    def roxy_workspaces(self):
        if self.config_store is None:
            return self.module.jsonify(ok=False, error="Free 配置服务尚未初始化"), 503
        try:
            from .free_roxy_runtime import RoxyBrowserClient
        except ImportError:
            from free_roxy_runtime import RoxyBrowserClient  # type: ignore[no-redef]
        try:
            result = RoxyBrowserClient(
                self.config_store.load()["roxybrowser"],
                log_fn=self.manager._log if self.manager else None,
            ).list_workspaces()
            return self.module.jsonify(ok=True, items=result)
        except Exception as exc:
            return self.error_response(
                exc,
                default_code="free_roxy_workspace",
                default_label="读取 RoxyBrowser 工作区",
                status=503,
            )

    def mailbox_url(self):
        if self.manager is None:
            return self._unavailable()
        data = self.module.request.get_json(silent=True) or {}
        row_id = str(data.get("row_id") or "") if isinstance(data, Mapping) else ""
        try:
            return self.module.jsonify(ok=True, mailbox_url=self.manager.pool.reveal_mailbox_url(row_id))
        except Exception as exc:
            status = 400 if isinstance(exc, ValueError) or getattr(exc, "retryable", None) is False else 503
            return self.error_response(
                exc,
                default_code="free_mailbox_url",
                default_label="读取 Free 取件地址",
                status=status,
            )

    def retry_twofa(self):
        if self.manager is None:
            return self._unavailable()
        data = self.module.request.get_json(silent=True) or {}
        if not isinstance(data, Mapping):
            return self.error_response(
                ValueError("请求必须是 JSON 对象"),
                default_code="free_twofa_retry",
                default_label="重试 Free 账号 2FA",
            )

        try:
            task = self.manager.retry_twofa(
                str(data.get("task_id") or data.get("row_id") or ""),
                self.config_store.load() if self.config_store is not None else {},
            )
            return self.module.jsonify(ok=True, task=task, state=self.free_state())
        except Exception as exc:
            return self.error_response(
                exc,
                default_code="free_twofa_retry",
                default_label="重试 Free 账号 2FA",
            )

    def rerun(self):
        if self.manager is None:
            return self._unavailable()
        data = self.module.request.get_json(silent=True) or {}
        if not isinstance(data, Mapping):
            return self.error_response(ValueError("请求必须是 JSON 对象"), default_code="free_rerun", default_label="重跑 Free 账号")
        try:
            result = self.manager.rerun(
                str(data.get("task_id") or ""),
                self.config_store.load() if self.config_store is not None else {},
            )
            return self.module.jsonify(ok=True, batch_id=result.get("batch_id"), batch={"batch_id": result.get("batch_id"), "members": result.get("tasks") or []}, state=self.free_state())
        except Exception as exc:
            return self.error_response(exc, default_code="free_rerun", default_label="重跑 Free 账号")

    def live_check(self):
        if self.manager is None:
            return self._unavailable()
        data = self.module.request.get_json(silent=True) or {}
        if not isinstance(data, Mapping):
            return self.error_response(
                ValueError("请求必须是 JSON 对象"),
                default_code="free_live_start",
                default_label="启动 Free 账号测活",
            )
        row_ids = data.get("row_ids")
        if not isinstance(row_ids, list):
            return self.error_response(
                FreeRegisterError("free_live_start", "启动 Free 账号测活", "请先选择要测活的 Free 账号", retryable=False),
                default_code="free_live_start",
                default_label="启动 Free 账号测活",
            )
        try:
            result = self._live_service().enqueue(row_ids, str(data.get("mode") or ""))
            if not result.get("accepted_count"):
                skipped = result.get("skipped") if isinstance(result.get("skipped"), list) else []
                reason = str((skipped[0] if skipped else {}).get("reason") or "没有符合条件的 Free 账号")
                raise FreeRegisterError("free_live_start", "启动 Free 账号测活", reason, retryable=False)
            return self.module.jsonify(
                ok=True,
                **result,
                rows=self.manager.pool.public_rows(),
            )
        except Exception as exc:
            return self.error_response(
                exc,
                default_code="free_live_start",
                default_label="启动 Free 账号测活",
            )

    def live_check_state(self):
        if self.manager is None:
            return self._unavailable()
        try:
            return self.module.jsonify(
                ok=True,
                state=self._live_service().public_state(),
                rows=self.manager.pool.public_rows(),
            )
        except Exception as exc:
            return self.error_response(
                exc,
                default_code="free_live_state",
                default_label="读取 Free 账号测活状态",
                status=503,
            )


__all__ = ["FreeAccountRouteController"]
