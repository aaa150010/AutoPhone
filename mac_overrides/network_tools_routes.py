"""Flask routes for the isolated proxy/network workbench."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

try:
    from .network_tools import NetworkToolError, NetworkToolsService
    from .free_register_common import safe_log_message
except ImportError:
    from network_tools import NetworkToolError, NetworkToolsService  # type: ignore[no-redef]
    from free_register_common import safe_log_message  # type: ignore[no-redef]


def _error_payload(exc: BaseException) -> dict[str, Any]:
    code = str(getattr(exc, "node_code", "network_tool") or "network_tool")
    label = str(getattr(exc, "node_label", "网络工具") or "网络工具")
    message = safe_log_message(exc)[:300] or f"{label}未返回错误详情"
    return {"ok": False, "error": f"{label} [{code}]：{message}", "failure": {"node_code": code, "node_label": label, "error_code": str(getattr(exc, "error_code", "") or f"{code}_failed"), "retryable": bool(getattr(exc, "retryable", True))}}


def install_network_routes(app: Any, *, module: Any, data_root: str | Path) -> NetworkToolsService:
    service = getattr(app, "_gptphone_network_tools", None)
    if service is None:
        service = NetworkToolsService(data_root)
        setattr(app, "_gptphone_network_tools", service)

    def body() -> Mapping[str, Any]:
        value = module.request.get_json(silent=True)
        return value if isinstance(value, Mapping) else {}

    def invoke(fn: Any, *args: Any, **kwargs: Any):
        try:
            value = fn(*args, **kwargs)
            if isinstance(value, Mapping):
                # Service methods may already return an explicit ``ok`` field
                # (notably proxy tests).  Copy before adding the default so
                # Flask's jsonify never receives duplicate keyword arguments.
                payload = dict(value)
                payload.setdefault("ok", True)
            else:
                payload = {"result": value, "ok": True}
            return module.jsonify(**payload)
        except NetworkToolError as exc:
            return module.jsonify(_error_payload(exc)), 400
        except Exception as exc:
            return module.jsonify(_error_payload(exc)), 500

    def proxies():
        return module.jsonify(ok=True, **service.public(), config=service.public_config())

    def config():
        if module.request.method == "GET":
            return module.jsonify(ok=True, config=service.public_config())
        return invoke(lambda: {"config": service.save_config(body())})

    def import_proxies():
        data = body()
        return invoke(service.import_text, str(data.get("proxy_content") or ""), country=str(data.get("country") or "ZZ"), group=str(data.get("group") or "默认组"), scheme=str(data.get("scheme") or "http"))

    def import_subscription():
        data = body()
        return invoke(service.import_subscription, str(data.get("subscription_url") or ""), str(data.get("content") or data.get("subscription_content") or ""), country=str(data.get("country") or "ZZ"), group=str(data.get("group") or "默认组"))

    def test():
        data = body()
        return invoke(service.test, str(data.get("proxy_id") or ""), mode=str(data.get("mode") or "quick"), target_url=str(data.get("target_url") or ""), exit_url=str(data.get("exit_url") or ""))

    def test_subscription():
        data = body()
        return invoke(service.test_subscription, str(data.get("subscription_id") or ""), target_url=str(data.get("target_url") or ""), exit_url=str(data.get("exit_url") or ""))

    def group():
        data = body()
        return invoke(service.update_group, country=str(data.get("country") or "ZZ"), group=str(data.get("group") or "默认组"), action=str(data.get("action") or ""), new_group=str(data.get("new_group") or ""), enabled=data.get("enabled"))

    routes = (
        ("/api/tools/proxies", "network_tools_proxies", proxies, ["GET"]),
        ("/api/tools/proxies/config", "network_tools_config", config, ["GET", "POST"]),
        ("/api/tools/proxies/import", "network_tools_import", import_proxies, ["POST"]),
        ("/api/tools/proxies/subscriptions", "network_tools_subscriptions", import_subscription, ["POST"]),
        ("/api/tools/proxies/test", "network_tools_test", test, ["POST"]),
        ("/api/tools/proxies/subscriptions/test", "network_tools_subscription_test", test_subscription, ["POST"]),
        ("/api/tools/proxies/group", "network_tools_group", group, ["POST"]),
        ("/api/tools/proxies/group/delete", "network_tools_group_delete", lambda: invoke(service.update_group, country=str(body().get("country") or "ZZ"), group=str(body().get("group") or "默认组"), action="delete"), ["POST"]),
    )
    for rule, endpoint, view, methods in routes:
        if endpoint not in app.view_functions:
            app.add_url_rule(rule, endpoint, view, methods=methods)
    return service


__all__ = ["install_network_routes"]
