"""Flask route assembly for the recovered web GUI."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable


@dataclass(frozen=True)
class WebRouteContext:
    module: Any
    app_dir: Path
    send_from_directory: Callable[..., Any]
    closure_values: Callable[[Callable[..., Any]], dict[str, Any]]
    lifecycle_lock: Any
    read_local_config: Callable[[], dict[str, Any]]
    write_local_config: Callable[[dict[str, Any]], dict[str, Any]]
    local_config_from_runtime: Callable[..., dict[str, Any]]
    local_config_secret: Callable[[str], Any]
    masked_local_config: Callable[[dict[str, Any]], dict[str, Any]]
    masked_state: Callable[[dict[str, Any]], dict[str, Any]]
    apply_server_defaults: Callable[[dict[str, Any]], dict[str, Any]]
    configure_sms_pool: Callable[..., str]
    preflight_sms_pool: Callable[..., list[dict[str, Any]]]
    safe_runtime_error: Callable[[Any], str]
    sms_alerts: Any
    sms_cost_ledger: Any
    sms_route_policy: Any
    sms_key_pool: Any
    sms_phone_gate: Any
    mailbox_admin_factory: Callable[[Any, Any, Any], Any]
    mailbox_manager_html: str


def patch_flask_app(app: Any, context: WebRouteContext) -> Any:
    """Install the macOS dashboard routes once on a recovered Flask app."""
    if getattr(app, "_gptphone_mac_patched", False):
        return app
    original_start = app.view_functions.get("start")
    if original_start is None:
        return app

    module = context.module
    closure = context.closure_values(original_start)
    importer = closure["importer"]
    logs = closure["logs"]
    settings = closure["settings"]
    state = closure["state"]
    store = closure["store"]
    mailbox_admin = context.mailbox_admin_factory(store, importer, logs)
    initial_config = store.load()
    context.write_local_config(
        context.local_config_from_runtime(initial_config, context.read_local_config())
    )
    context.configure_sms_pool(initial_config, logs=logs, importer=importer)

    frontend_dist = context.app_dir / "frontend" / "dist"

    def spa_index():
        return context.send_from_directory(str(frontend_dist), "index.html")

    def spa_asset(filename):
        return context.send_from_directory(str(frontend_dist / "assets"), filename)

    if frontend_dist.exists():
        if "index" in app.view_functions:
            app.view_functions["index"] = spa_index
        else:
            app.add_url_rule("/", "index", spa_index, methods=["GET"])
        if "spa_asset" not in app.view_functions:
            app.add_url_rule("/assets/<path:filename>", "spa_asset", spa_asset, methods=["GET"])

    def public_state():
        return context.masked_state(state())

    def busy_response(message="另一个配置、预检或启动请求正在处理中"):
        return module.jsonify(ok=False, error=message, state=public_state()), 409

    def restore_active_config(previous_config, previous_local_config):
        rollback_failed = False
        for action in (
            lambda: store.save(previous_config),
            lambda: context.configure_sms_pool(previous_config, logs=logs, importer=importer),
            lambda: context.write_local_config(previous_local_config),
        ):
            try:
                action()
            except Exception:
                rollback_failed = True
        if rollback_failed:
            logs.add("配置应用失败，上一版本未能完整恢复，请重新保存配置", "error")

    def save_active_config(data):
        previous_config = store.load()
        previous_local_config = context.read_local_config()
        prepared = context.apply_server_defaults(data)
        try:
            saved = store.save(prepared)
            context.configure_sms_pool(saved, logs=logs, importer=importer)
            local_config = context.local_config_from_runtime(saved, previous_local_config)
            context.write_local_config(local_config)
        except Exception:
            restore_active_config(previous_config, previous_local_config)
            raise
        return saved

    def api_state():
        return module.jsonify(ok=True, state=public_state())

    if "api_state" in app.view_functions:
        app.view_functions["api_state"] = api_state

    def save_config():
        if not context.lifecycle_lock.acquire(blocking=False):
            return busy_response()
        try:
            if importer.status(settings()).get("running"):
                return module.jsonify(
                    ok=False,
                    error="任务运行中，停止后才能修改配置",
                    state=public_state(),
                ), 409
            data = module.request.get_json(silent=True) or {}
            if not isinstance(data, dict):
                return module.jsonify(ok=False, error="配置必须是 JSON 对象"), 400
            data.pop("pool_content", None)
            saved = save_active_config(data)
            logs.add("独立导入器配置已保存到本工具 data 目录", "success")
            return module.jsonify(
                ok=True,
                settings=context.masked_local_config(saved),
                state=public_state(),
            )
        except ValueError as exc:
            safe = context.safe_runtime_error(exc)
            return module.jsonify(ok=False, error=safe, state=public_state()), 400
        except Exception as exc:
            safe = context.safe_runtime_error(exc)
            logs.add(f"保存配置失败: {safe}", "error")
            return module.jsonify(
                ok=False,
                error=f"保存配置失败: {safe}",
                state=public_state(),
            ), 500
        finally:
            context.lifecycle_lock.release()

    if "save_config" in app.view_functions:
        app.view_functions["save_config"] = save_config

    def stop():
        with context.lifecycle_lock:
            importer.stop()
        return module.jsonify(ok=True, state=public_state())

    if "stop" in app.view_functions:
        app.view_functions["stop"] = stop

    def preflight():
        if not context.lifecycle_lock.acquire(blocking=False):
            return busy_response()
        try:
            if importer.status(settings()).get("running"):
                return module.jsonify(
                    ok=False,
                    error="任务运行中，停止后才能执行预检",
                    state=public_state(),
                ), 409
            data = module.request.get_json(silent=True) or {}
            if not isinstance(data, dict):
                return module.jsonify(ok=False, error="配置必须是 JSON 对象"), 400
            try:
                context.sms_alerts.begin_run()
                config = save_active_config(data)
                statuses = context.preflight_sms_pool(config, logs=logs, importer=importer)
                result = importer.settings_validation(config, remote=True)
            except Exception as exc:
                safe = context.safe_runtime_error(exc)
                logs.add(f"SMS 预检失败: {safe}", "error")
                return module.jsonify(
                    ok=False,
                    error=safe,
                    sms_key_statuses=context.sms_key_pool.public_statuses(),
                    state=public_state(),
                ), 400
            logs.add(
                f"预检通过: 邮箱池 {result['pool']['entries']} 条，"
                f"SUB2 分组 {result['sub2_group']}#{result['sub2_group_id']}",
                "success",
            )
            return module.jsonify(
                ok=True,
                result=result,
                sms_key_statuses=statuses,
                state=public_state(),
            )
        finally:
            context.lifecycle_lock.release()

    if "preflight" in app.view_functions:
        app.view_functions["preflight"] = preflight

    @app.after_request
    def no_cache_response(response):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        return response

    def start_from_request(*, replace_pool: bool):
        if not context.lifecycle_lock.acquire(blocking=False):
            return busy_response("另一个启动请求正在处理中")
        try:
            if importer.status(settings()).get("running"):
                return module.jsonify(
                    ok=False,
                    error="已有任务运行中，请先停止并等待任务结束",
                    state=public_state(),
                ), 409

            data = module.request.get_json(silent=True) or {}
            if not isinstance(data, dict):
                return module.jsonify(ok=False, error="配置必须是 JSON 对象"), 400

            pool_content = data.pop("pool_content", "")
            auto_content = module._clean(pool_content) if replace_pool else ""

            if auto_content:
                path = store.save_pool_text(auto_content)
                data.update({"email_mode": "auto", "pool_path": str(path)})
            cfg = save_active_config(data)
            pool = importer._pool(cfg)

            if auto_content:
                check = pool.validate()
                if not check.get("ok"):
                    return module.jsonify(
                        ok=False,
                        error="; ".join(check.get("errors") or ["邮箱池为空"]),
                        state=public_state(),
                    ), 400
                cleared = pool.reset_for_pool_replacement()
                logs.add(
                    f"本次启动已覆盖自动邮箱池: {check['entries']} 条，清除旧状态 {cleared} 条",
                    "success",
                )
            else:
                check = pool.validate()
                if not check.get("ok"):
                    return module.jsonify(
                        ok=False,
                        error="; ".join(check.get("errors") or ["邮箱池为空"]),
                        state=public_state(),
                    ), 400

            if not replace_pool:
                logs.add(f"使用现有自动邮箱池启动: {check['entries']} 条", "info")
            context.sms_alerts.begin_run()
            context.sms_cost_ledger.clear()
            context.sms_route_policy.reset()
            context.sms_key_pool.begin_run()
            context.sms_phone_gate.begin_run()
            try:
                context.preflight_sms_pool(cfg, logs=logs, importer=importer)
            except ValueError as exc:
                return module.jsonify(
                    ok=False,
                    error=context.safe_runtime_error(exc),
                    state=public_state(),
                ), 400
            importer.start(cfg)
            return module.jsonify(ok=True, state=public_state())
        except Exception as exc:
            safe = context.safe_runtime_error(exc)
            logs.add(f"启动失败: {safe}", "error")
            return module.jsonify(ok=False, error=f"启动失败: {safe}", state=public_state()), 500
        finally:
            context.lifecycle_lock.release()

    def start():
        return start_from_request(replace_pool=True)

    app.view_functions["start"] = start

    def start_existing():
        return start_from_request(replace_pool=False)

    if "start_existing" not in app.view_functions:
        app.add_url_rule("/api/start-existing", "start_existing", start_existing, methods=["POST"])

    def mailbox_manager():
        if frontend_dist.exists():
            return spa_index()
        return module.Response(context.mailbox_manager_html, mimetype="text/html")

    def api_mailboxes():
        return module.jsonify(mailbox_admin.list_mailboxes())

    def mailbox_mutation(operation: str, action: Callable[[dict[str, Any]], dict[str, Any]]):
        try:
            data = module.request.get_json(silent=True) or {}
            result = action(data)
            if not result.get("ok"):
                return module.jsonify(result), 400
            result["mailboxes"] = mailbox_admin.list_mailboxes()
            result["state"] = public_state()
            return module.jsonify(result)
        except Exception as exc:
            safe = module._safe(exc) if hasattr(module, "_safe") else str(exc)
            logs.add(f"邮箱管理{operation}失败: {safe}", "error")
            return module.jsonify(ok=False, error=f"邮箱管理{operation}失败: {safe}"), 500

    def api_mailboxes_import():
        def action(data):
            return mailbox_admin.import_mailboxes(data.get("pool_content", ""))

        return mailbox_mutation("导入", action)

    def api_mailboxes_delete():
        return mailbox_mutation("删除", mailbox_admin.delete_mailboxes)

    def api_mailboxes_restore():
        return mailbox_mutation("放回可领取", mailbox_admin.restore_mailboxes)

    def api_mailboxes_latest_code():
        try:
            data = module.request.get_json(silent=True) or {}
            result = mailbox_admin.latest_code(data)
            if not result.get("ok"):
                return module.jsonify(result), 400
            return module.jsonify(result)
        except Exception as exc:
            safe = module._safe(exc) if hasattr(module, "_safe") else str(exc)
            logs.add(f"邮箱管理查码失败: {safe}", "error")
            return module.jsonify(ok=False, error=f"邮箱管理查码失败: {safe}"), 500

    def api_local_config():
        return module.jsonify(
            ok=True,
            config=context.masked_local_config(context.read_local_config()),
        )

    def api_local_config_export():
        try:
            data = module.request.get_json(silent=True) or {}
            download = bool(data.pop("download", False)) if isinstance(data, dict) else False
            config = context.local_config_from_runtime(data, context.read_local_config())
            return module.jsonify(
                ok=True,
                config=config if download else context.masked_local_config(config),
            )
        except Exception as exc:
            safe = module._safe(exc) if hasattr(module, "_safe") else str(exc)
            return module.jsonify(ok=False, error=f"导出本地配置失败: {safe}"), 500

    def api_local_config_import():
        if not context.lifecycle_lock.acquire(blocking=False):
            return busy_response()
        try:
            if importer.status(settings()).get("running"):
                return module.jsonify(
                    ok=False,
                    error="任务运行中，停止后才能导入配置",
                    state=public_state(),
                ), 409
            data = module.request.get_json(silent=True) or {}
            config = data.get("config") if isinstance(data, dict) else {}
            if not isinstance(config, dict):
                return module.jsonify(ok=False, error="配置 JSON 必须是对象"), 400
            config = context.write_local_config(
                context.local_config_from_runtime(config, context.read_local_config())
            )
            return module.jsonify(ok=True, config=context.masked_local_config(config))
        except Exception as exc:
            safe = module._safe(exc) if hasattr(module, "_safe") else str(exc)
            return module.jsonify(ok=False, error=f"导入本地配置失败: {safe}"), 500
        finally:
            context.lifecycle_lock.release()

    def api_local_config_secret():
        try:
            data = module.request.get_json(silent=True) or {}
            value = context.local_config_secret(data.get("id") if isinstance(data, dict) else "")
            if not value:
                return module.jsonify(ok=False, error="本地配置没有保存这个密钥"), 404
            return module.jsonify(ok=True, value=value)
        except Exception as exc:
            safe = module._safe(exc) if hasattr(module, "_safe") else str(exc)
            return module.jsonify(ok=False, error=f"读取本地密钥失败: {safe}"), 500

    routes = (
        ("/mailboxes", "mailbox_manager", mailbox_manager, ["GET"]),
        ("/api/mailboxes", "api_mailboxes", api_mailboxes, ["GET"]),
        ("/api/mailboxes/import", "api_mailboxes_import", api_mailboxes_import, ["POST"]),
        ("/api/mailboxes/delete", "api_mailboxes_delete", api_mailboxes_delete, ["POST"]),
        ("/api/mailboxes/restore", "api_mailboxes_restore", api_mailboxes_restore, ["POST"]),
        ("/api/mailboxes/latest-code", "api_mailboxes_latest_code", api_mailboxes_latest_code, ["POST"]),
        ("/api/local-config", "api_local_config", api_local_config, ["GET"]),
        ("/api/local-config/export", "api_local_config_export", api_local_config_export, ["POST"]),
        ("/api/local-config/import", "api_local_config_import", api_local_config_import, ["POST"]),
        ("/api/local-config/secret", "api_local_config_secret", api_local_config_secret, ["POST"]),
    )
    for rule, endpoint, view_func, methods in routes:
        if endpoint not in app.view_functions:
            app.add_url_rule(rule, endpoint, view_func, methods=methods)

    app._gptphone_mac_patched = True
    return app
