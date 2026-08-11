"""Narrow runtime route for the OpenAI connectivity rollback switch."""

from __future__ import annotations

import threading
from typing import Any, Callable

try:
    from .route_failures import explicit_failure_payload
except ImportError:  # Loaded as a top-level runtime override.
    from route_failures import explicit_failure_payload  # type: ignore[no-redef]


def patch_openai_connectivity_guard_route(
    app: Any,
    *,
    module: Any,
    lifecycle_lock: Any,
    store: Any,
    logs: Any,
    state_getter: Callable[[], Any],
    read_local_config: Callable[[], dict[str, Any]],
    write_local_config: Callable[[dict[str, Any]], dict[str, Any]],
    masked_local_config: Callable[[dict[str, Any]], dict[str, Any]],
    masked_state: Callable[[dict[str, Any]], dict[str, Any]],
    diagnostics: Any = None,
) -> Any:
    """Allow only the guard flag to change while a batch is active."""

    endpoint = "api_openai_connectivity_guard"
    if (
        endpoint in app.view_functions
        or store is None
        or logs is None
        or not callable(state_getter)
    ):
        return app

    def public_state() -> dict[str, Any]:
        return masked_state(state_getter())

    diagnostic_lock = threading.Lock()

    def run_diagnostics():
        if diagnostics is None or not callable(getattr(diagnostics, "run", None)):
            return module.jsonify(explicit_failure_payload(
                node_code="openai_connectivity_diagnostic",
                node_label="OpenAI 链路诊断",
                error_code="openai_connectivity_diagnostic_unavailable",
                cause="诊断运行时不可用",
                retryable=False,
                http_status=503,
            )), 503
        if not diagnostic_lock.acquire(blocking=False):
            return module.jsonify(explicit_failure_payload(
                node_code="openai_connectivity_diagnostic",
                node_label="OpenAI 链路诊断",
                error_code="openai_connectivity_diagnostic_busy",
                cause="已有一次诊断正在运行，请等待当前诊断完成",
                retryable=True,
                http_status=409,
            )), 409
        try:
            report = diagnostics.run()
            return module.jsonify(ok=True, diagnostic=report)
        except Exception as exc:
            return module.jsonify(explicit_failure_payload(
                node_code="openai_connectivity_diagnostic",
                node_label="OpenAI 链路诊断",
                error_code="openai_connectivity_diagnostic_failed",
                cause=f"诊断运行时出现未处理异常（{type(exc).__name__}）",
                retryable=True,
                http_status=500,
            )), 500
        finally:
            diagnostic_lock.release()

    def update_guard():
        if not lifecycle_lock.acquire(blocking=False):
            return module.jsonify(explicit_failure_payload(
                node_code="openai_connectivity_guard",
                node_label="OpenAI 链路保护",
                error_code="openai_connectivity_guard_busy",
                cause="另一个配置、预检或启动请求正在处理中",
                state=public_state(),
                retryable=True,
                http_status=409,
            )), 409
        try:
            data = module.request.get_json(silent=True) or {}
            enabled = data.get("enabled") if isinstance(data, dict) else None
            if not isinstance(enabled, bool):
                return module.jsonify(explicit_failure_payload(
                    node_code="openai_connectivity_guard",
                    node_label="OpenAI 链路保护",
                    error_code="openai_connectivity_guard_invalid_value",
                    cause="开关值必须是布尔值",
                    retryable=False,
                    http_status=400,
                )), 400
            previous_config = store.load()
            previous_local = read_local_config()
            try:
                updated = dict(previous_config)
                updated["openai_connectivity_guard"] = enabled
                saved = dict(store.save(updated) or updated)
                local = dict(previous_local)
                local["openai_connectivity_guard"] = enabled
                write_local_config(local)
            except Exception:
                for restore in (
                    lambda: store.save(previous_config),
                    lambda: write_local_config(previous_local),
                ):
                    try:
                        restore()
                    except Exception:
                        pass
                logs.add("OpenAI 链路保护开关更新失败", "error")
                return module.jsonify(explicit_failure_payload(
                    node_code="openai_connectivity_guard",
                    node_label="OpenAI 链路保护",
                    error_code="openai_connectivity_guard_update_failed",
                    cause="开关写入失败，原配置已尝试恢复",
                    retryable=True,
                    http_status=500,
                )), 500
            logs.add(
                "OpenAI 链路保护已开启" if enabled else "OpenAI 链路保护已关闭",
                "info" if enabled else "warn",
            )
            return module.jsonify(
                ok=True,
                enabled=enabled,
                settings=masked_local_config(saved),
                state=public_state(),
            )
        finally:
            lifecycle_lock.release()

    app.add_url_rule(
        "/api/openai-connectivity-guard",
        endpoint,
        update_guard,
        methods=["POST"],
    )
    if "api_openai_connectivity_diagnostics" not in app.view_functions:
        app.add_url_rule(
            "/api/openai-connectivity-diagnostics",
            "api_openai_connectivity_diagnostics",
            run_diagnostics,
            methods=["POST"],
        )
    return app


__all__ = ["patch_openai_connectivity_guard_route"]
