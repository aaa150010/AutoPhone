"""Narrow runtime route for the OpenAI connectivity rollback switch."""

from __future__ import annotations

from typing import Any, Callable


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

    def update_guard():
        if not lifecycle_lock.acquire(blocking=False):
            return module.jsonify(
                ok=False,
                error="另一个配置、预检或启动请求正在处理中",
                state=public_state(),
            ), 409
        try:
            data = module.request.get_json(silent=True) or {}
            enabled = data.get("enabled") if isinstance(data, dict) else None
            if not isinstance(enabled, bool):
                return module.jsonify(
                    ok=False,
                    error="OpenAI 链路保护开关必须是布尔值",
                ), 400
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
                return module.jsonify(
                    ok=False,
                    node_code="openai_connectivity_guard",
                    node_label="OpenAI 链路保护",
                    error_code="openai_connectivity_guard_update_failed",
                    error="OpenAI 链路保护 [OpenAI 链路保护/openai_connectivity_guard]：开关更新失败",
                ), 500
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
    return app


__all__ = ["patch_openai_connectivity_guard_route"]
