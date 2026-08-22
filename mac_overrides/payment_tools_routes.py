"""Flask routes for the isolated payment-link workbench."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

try:
    from .payment_tools import PaymentToolError, PaymentToolsService
    from .free_register_common import safe_log_message
except ImportError:  # loaded as a top-level override
    from payment_tools import PaymentToolError, PaymentToolsService  # type: ignore[no-redef]
    from free_register_common import safe_log_message  # type: ignore[no-redef]


def _error_payload(exc: BaseException) -> dict[str, Any]:
    code = str(getattr(exc, "node_code", "payment_task") or "payment_task")
    label = str(getattr(exc, "node_label", "支付工具") or "支付工具")
    message = safe_log_message(exc)[:300] or f"{label}未返回错误详情"
    return {
        "ok": False,
        "error": f"{label} [{code}]：{message}",
        "failure": {
            "node_code": code,
            "node_label": label,
            "error_code": str(getattr(exc, "error_code", "") or f"{code}_failed"),
            "retryable": bool(getattr(exc, "retryable", True)),
        },
    }


def install_payment_routes(app: Any, *, module: Any, data_root: str | Path, free_manager: Any | None = None) -> PaymentToolsService:
    """Attach payment routes once and return the per-app service instance."""
    service = getattr(app, "_gptphone_payment_tools", None)
    if service is None:
        service = PaymentToolsService(data_root, free_manager=free_manager)
        setattr(app, "_gptphone_payment_tools", service)

    def payload() -> Mapping[str, Any]:
        value = module.request.get_json(silent=True)
        return value if isinstance(value, Mapping) else {}

    def respond(callable_: Any, *args: Any, **kwargs: Any):
        try:
            return module.jsonify(ok=True, **callable_(*args, **kwargs))
        except PaymentToolError as exc:
            return module.jsonify(_error_payload(exc)), 400
        except Exception as exc:  # keep implementation failures structured
            return module.jsonify(_error_payload(exc)), 500

    def config():
        if module.request.method == "GET":
            return module.jsonify(ok=True, config=service.public_config(), state=service.state())
        return respond(lambda: {"config": service.save_config(payload()), "state": service.state()})

    def tasks():
        return module.jsonify(ok=True, **service.state())

    def task(task_id: str):
        return respond(lambda: {"task": service.task(task_id)})

    def logs(task_id: str):
        return respond(lambda: {"task_id": task_id, "logs": service.logs(task_id)})

    def create_task():
        return respond(service.create, payload())

    def confirm(task_id: str):
        data = payload()
        target_domain = str(data.get("target_domain") or "").strip().casefold()
        return respond(lambda: {"task": service.confirm(task_id, target_domain)})

    def cancel(task_id: str):
        return respond(lambda: {"task": service.cancel(task_id)})

    def retry(task_id: str):
        return respond(lambda: {"task": service.retry(task_id)})

    def secret(task_id: str):
        return respond(lambda: {"task_id": task_id, "value": service.reveal(task_id)})

    routes = (
        ("/api/tools/payment/config", "payment_tools_config", config, ["GET", "POST"]),
        ("/api/tools/payment/tasks", "payment_tools_tasks", tasks, ["GET"]),
        ("/api/tools/payment/tasks", "payment_tools_create_task", create_task, ["POST"]),
        ("/api/tools/payment/tasks/<task_id>", "payment_tools_task", task, ["GET"]),
        ("/api/tools/payment/tasks/<task_id>/logs", "payment_tools_logs", logs, ["GET"]),
        ("/api/tools/payment/tasks/<task_id>/confirm", "payment_tools_confirm", confirm, ["POST"]),
        ("/api/tools/payment/tasks/<task_id>/cancel", "payment_tools_cancel", cancel, ["POST"]),
        ("/api/tools/payment/tasks/<task_id>/retry", "payment_tools_retry", retry, ["POST"]),
        ("/api/tools/payment/tasks/<task_id>/secret", "payment_tools_secret", secret, ["GET", "POST"]),
    )
    for rule, endpoint, view, methods in routes:
        if endpoint not in app.view_functions:
            app.add_url_rule(rule, endpoint, view, methods=methods)
    return service


__all__ = ["install_payment_routes"]
