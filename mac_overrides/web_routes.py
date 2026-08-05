"""Flask route assembly for the recovered web GUI."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import time
from typing import Any, Callable
import uuid


_PIXEL_AUTO_TARGET_IDS = tuple(f"pixel-{index}" for index in range(2, 8))


def _safe_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _normalize_run_mailbox_rows(value: Any) -> list[dict[str, Any]] | None:
    """Validate a one-run mailbox selection without accepting mailbox content."""
    if value is None:
        return []
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return None
    normalized: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()
    for item in value:
        if not isinstance(item, Mapping):
            return None
        row_id = str(item.get("row_id") or "").strip().lower()
        line_no = _safe_int(item.get("line_no"), 0)
        if not row_id or line_no <= 0 or len(row_id) > 128:
            return None
        binding = (row_id, line_no)
        if binding in seen:
            continue
        seen.add(binding)
        normalized.append({"row_id": row_id, "line_no": line_no})
    return normalized


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
    test_email_notification: Callable[[dict[str, Any]], dict[str, Any]]
    sms_alerts: Any
    sms_cost_ledger: Any
    sms_route_policy: Any
    sms_key_pool: Any
    sms_phone_gate: Any
    mailbox_admin_factory: Callable[[Any, Any, Any], Any]
    mailbox_manager_html: str
    pixel_client: Any | None = None
    pixel_upload_queue: Any | None = None
    pixel_payload_builder: Callable[[Mapping[str, Any]], dict[str, Any]] | None = None
    mailbox_url_test_factory: Callable[[], Any] | None = None


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
    if context.pixel_upload_queue is not None:
        context.pixel_upload_queue.log_fn = logs.add
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

            run_mailbox_rows = _normalize_run_mailbox_rows(data.pop("run_mailbox_rows", None))
            if run_mailbox_rows is None:
                return module.jsonify(
                    ok=False,
                    error="本次运行的邮箱行绑定参数无效",
                ), 400

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
            run_config = dict(cfg)
            batch_started_at = int(time.time())
            run_config["batch_started_at"] = batch_started_at
            run_config["batch_id"] = (
                f"{time.strftime('%Y%m%d-%H%M%S', time.localtime(batch_started_at))}-"
                f"{uuid.uuid4().hex[:6]}"
            )
            if run_mailbox_rows:
                run_config["_gptphone_run_mailbox_rows"] = run_mailbox_rows
            importer.start(run_config)
            return module.jsonify(ok=True, state=public_state())
        except ValueError as exc:
            safe = context.safe_runtime_error(exc)
            return module.jsonify(ok=False, error=safe, state=public_state()), 400
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

    def mailbox_url_test_page():
        if frontend_dist.exists():
            return spa_index()
        return module.Response(context.mailbox_manager_html, mimetype="text/html")

    def api_mailbox_url_test():
        factory = context.mailbox_url_test_factory
        if factory is None:
            return module.jsonify(ok=False, error="URL 取件测试尚未启用"), 503
        try:
            data = module.request.get_json(silent=True) or {}
            if not isinstance(data, dict):
                return module.jsonify(ok=False, error="请求必须是 JSON 对象"), 400
            value = data.get("value") or data.get("url") or ""
            local = context.read_local_config()
            proxy_scope = local.get("proxy_scope") if isinstance(local.get("proxy_scope"), Mapping) else {}
            proxy = str(local.get("proxy") or "") if bool(proxy_scope.get("email")) else ""
            result = factory().test(
                value,
                timeout_seconds=60,
                interval_seconds=5,
                resend_after_seconds=15,
                proxy=proxy,
            )
            status = 400 if result.get("code") == "mailbox_url_invalid" else 200
            return module.jsonify(result), status
        except Exception:
            logs.add("URL 取件测试失败 [测试取件地址/mailbox_url_test]：未返回可用诊断", "error")
            return module.jsonify(
                ok=False,
                code="mailbox_url_test_failed",
                error="URL 取件测试失败：未返回可用诊断",
            ), 500

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

    def api_mailboxes_password():
        try:
            data = module.request.get_json(silent=True) or {}
            if not isinstance(data, dict):
                return module.jsonify(ok=False, error="请求必须是 JSON 对象"), 400
            result = mailbox_admin.reveal_password(data.get("row_id"), data.get("line_no"))
            if result.get("ok"):
                return module.jsonify(result)
            status = 409 if result.get("code") == "mailbox_row_stale" else 400
            return module.jsonify(result), status
        except Exception:
            return module.jsonify(ok=False, error="读取邮箱密码失败"), 500

    def api_mailboxes_totp():
        try:
            data = module.request.get_json(silent=True) or {}
            if not isinstance(data, dict):
                return module.jsonify(ok=False, error="请求必须是 JSON 对象"), 400
            result = mailbox_admin.reveal_totp(data.get("row_id"), data.get("line_no"))
            if result.get("ok"):
                return module.jsonify(result)
            status = 409 if result.get("code") == "mailbox_row_stale" else 400
            return module.jsonify(result), status
        except Exception:
            return module.jsonify(ok=False, error="读取 2FA 密钥失败"), 500

    def api_mailboxes_sub2_test():
        try:
            data = module.request.get_json(silent=True) or {}
            if not isinstance(data, dict):
                return module.jsonify(ok=False, error="请求必须是 JSON 对象"), 400
            result = mailbox_admin.sub2_test(data)
            if not isinstance(result, Mapping):
                return module.jsonify(ok=False, error="SUB2 批量连接测试失败"), 502
            response = dict(result)
            if response.get("ok"):
                response["mailboxes"] = mailbox_admin.list_mailboxes()
                response["state"] = public_state()
                return module.jsonify(response)
            code = str(response.get("code") or "")
            if code == "mailbox_rows_stale":
                status = 409
            elif code.startswith("sub2_admin_") or code == "sub2_batch_failed":
                status = 502
            elif code == "sub2_not_configured":
                status = 503
            else:
                status = 400
            return module.jsonify(response), status
        except Exception:
            logs.add("SUB2 批量连接测试失败", "error")
            return module.jsonify(ok=False, error="SUB2 批量连接测试失败"), 502

    def api_mailboxes_quota():
        try:
            data = module.request.get_json(silent=True) or {}
            if not isinstance(data, dict):
                return module.jsonify(ok=False, error="请求必须是 JSON 对象"), 400
            result = mailbox_admin.query_openai_quotas(data)
            if not isinstance(result, Mapping):
                return module.jsonify(ok=False, error="OpenAI 额度查询失败"), 502
            if result.get("ok"):
                return module.jsonify(result)
            code = str(result.get("code") or "")
            status = 409 if code == "mailbox_rows_stale" else 400
            if code.startswith("openai_quota_"):
                status = 503
            return module.jsonify(dict(result)), status
        except Exception:
            logs.add("邮箱管理 OpenAI 额度查询失败", "error")
            return module.jsonify(
                ok=False,
                code="openai_quota_failed",
                error="查询 OpenAI 额度失败：未返回可用诊断",
            ), 502

    def mailbox_selection_error(result: Mapping[str, Any]):
        code = str(result.get("code") or "")
        status = 409 if code == "mailbox_rows_stale" else 400
        return module.jsonify(dict(result)), status

    def api_mailboxes_pixel_retry():
        if context.pixel_upload_queue is None:
            return pixel_unavailable(queue=True)
        try:
            selected = mailbox_admin.selected_success_results(request_json_object())
            if not selected.get("ok"):
                return mailbox_selection_error(selected)
            records = []
            for item in selected.get("items") or []:
                records.append(
                    context.pixel_upload_queue.requeue(item["task_id"], item["result_file"])
                )
            logs.add(f"邮箱管理已将 {len(records)} 个账号重新加入 Pixel 上传队列", "success")
            return module.jsonify(
                ok=True,
                queued=len(records),
                skipped=int(selected.get("skipped") or 0),
                records=records,
                mailboxes=mailbox_admin.list_mailboxes(),
                state=public_state(),
            )
        except Exception as exc:
            return pixel_error_response(exc)

    def api_mailboxes_sub2_export():
        if context.pixel_payload_builder is None:
            return module.jsonify(ok=False, error="SUB2API 导出尚未配置"), 503
        try:
            selected = mailbox_admin.selected_success_results(request_json_object())
            if not selected.get("ok"):
                return mailbox_selection_error(selected)
            accounts = []
            now = int(time.time())
            for item in selected.get("items") or []:
                payload = context.pixel_payload_builder(item["document"])
                source_account = payload["accounts"][0]
                source_credentials = dict(source_account.get("credentials") or {})
                account_id = str(
                    source_credentials.get("chatgpt_account_id")
                    or source_credentials.get("account_id")
                    or ""
                ).strip()
                credentials = {
                    "access_token": source_credentials.get("access_token") or "",
                    "chatgpt_account_id": account_id,
                    "client_id": source_credentials.get("client_id") or "",
                    "expires_at": _safe_int(source_credentials.get("expires_at"), now + 864_000),
                    "expires_in": _safe_int(source_credentials.get("expires_in"), 863_999),
                    "model_mapping": {
                        "gpt-5.4": "gpt-5.4",
                        "gpt-5.4-mini": "gpt-5.4-mini",
                        "gpt-5.5": "gpt-5.5",
                        "gpt-5.6-luna": "gpt-5.6-luna",
                        "gpt-5.6-terra": "gpt-5.6-terra",
                    },
                    "organization_id": source_credentials.get("workspace_id") or "",
                    "refresh_token": source_credentials.get("refresh_token") or "",
                }
                accounts.append(
                    {
                        "name": str(source_credentials.get("email") or item["email"])[:64],
                        "platform": "openai",
                        "type": "oauth",
                        "credentials": credentials,
                        "extra": {
                            "load_factor": 10,
                            "openai_oauth_responses_websockets_v2_enabled": True,
                            "openai_oauth_responses_websockets_v2_mode": "passthrough",
                        },
                        "concurrency": 10,
                        "priority": 1,
                        "rate_multiplier": 1.0,
                        "auto_pause_on_expired": True,
                    }
                )
            exported_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            return module.jsonify(
                ok=True,
                count=len(accounts),
                skipped=int(selected.get("skipped") or 0),
                filename=f"sub2api-{time.strftime('%Y%m%d-%H%M%S')}.json",
                export={"exported_at": exported_at, "proxies": [], "accounts": accounts},
            )
        except Exception as exc:
            public_message = getattr(exc, "public_message", "")
            if public_message:
                return module.jsonify(ok=False, error=str(public_message)), 400
            logs.add("邮箱管理 SUB2API 导出失败", "error")
            return module.jsonify(ok=False, error="SUB2API 导出失败，请确认所选账号结果完整"), 400

    def pixel_error_response(exc: Exception):
        public_message = getattr(exc, "public_message", "")
        if public_message:
            try:
                status = int(getattr(exc, "status_code", 500) or 500)
            except (TypeError, ValueError):
                status = 500
            if status < 400 or status > 599:
                status = 500
            return module.jsonify(ok=False, error=str(public_message)), status
        logs.add("Pixel 管理操作失败", "error")
        return module.jsonify(ok=False, error="Pixel 管理操作失败"), 500

    def pixel_unavailable(*, queue: bool = False):
        name = "Pixel 上传队列" if queue else "Pixel 管理服务"
        return module.jsonify(ok=False, error=f"{name}尚未配置"), 503

    def pixel_json_result(value: Any, **extra: Any):
        payload = dict(value) if isinstance(value, Mapping) else {}
        payload.update(extra)
        payload.setdefault("ok", True)
        return module.jsonify(payload)

    def request_json_object() -> dict[str, Any]:
        value = module.request.get_json(silent=True) or {}
        return dict(value) if isinstance(value, Mapping) else {}

    def account_ids_from(data: Mapping[str, Any]) -> list[Any]:
        values = data.get("account_ids")
        if values is None:
            values = data.get("accountIds")
        if not isinstance(values, Sequence) or isinstance(values, (str, bytes)):
            return []
        return list(values)

    def target_ids_from(data: Mapping[str, Any]) -> list[str] | None:
        values: Any = None
        for key in ("target_ids", "targetIds"):
            if key in data:
                values = data.get(key)
                break
        if values is None:
            for key in ("target_id", "targetId"):
                if key in data:
                    values = [data.get(key)]
                    break
        if values is None:
            return None
        if isinstance(values, (str, bytes)):
            values = [values]
        if not isinstance(values, Sequence):
            return []
        result: list[str] = []
        for value in values:
            target_id = str(value or "").strip()
            if target_id and target_id not in result:
                result.append(target_id)
        return result

    def pixel_target_rejected(target_id: Any):
        normalized = str(target_id or "").strip()
        if normalized in _PIXEL_AUTO_TARGET_IDS:
            return None
        return module.jsonify(
            ok=False,
            error="Pixel 账号管理：该目标未开放（仅支持 pixel-2 至 pixel-7）",
        ), 404

    def api_pixel_targets():
        if context.pixel_client is None:
            return pixel_unavailable()
        try:
            result = context.pixel_client.targets()
            payload = dict(result) if isinstance(result, Mapping) else {}
            targets = payload.get("targets")
            if isinstance(targets, list):
                public_targets = []
                for value in targets:
                    if not isinstance(value, Mapping):
                        continue
                    item = dict(value)
                    target_id = str(
                        item.get("id") or item.get("target_id") or item.get("targetId") or ""
                    ).strip()
                    if target_id not in _PIXEL_AUTO_TARGET_IDS:
                        continue
                    item["autoUpload"] = target_id in _PIXEL_AUTO_TARGET_IDS
                    item["excluded"] = False
                    public_targets.append(item)
                payload["targets"] = public_targets
            return pixel_json_result(payload)
        except Exception as exc:
            return pixel_error_response(exc)

    def api_pixel_accounts(target_id: str):
        rejected = pixel_target_rejected(target_id)
        if rejected is not None:
            return rejected
        if context.pixel_client is None:
            return pixel_unavailable()
        try:
            page_size = module.request.args.get("page_size")
            if page_size is None:
                page_size = module.request.args.get("pageSize", 50)
            result = context.pixel_client.accounts(
                target_id,
                page=module.request.args.get("page", 1),
                page_size=page_size,
                search=module.request.args.get("search", ""),
                status=module.request.args.get("status", ""),
            )
            return pixel_json_result(result)
        except Exception as exc:
            return pixel_error_response(exc)

    def api_pixel_accounts_bulk_test(target_id: str):
        rejected = pixel_target_rejected(target_id)
        if rejected is not None:
            return rejected
        if context.pixel_client is None:
            return pixel_unavailable()
        try:
            data = request_json_object()
            result = context.pixel_client.bulk_test(target_id, account_ids_from(data))
            return pixel_json_result(result)
        except Exception as exc:
            return pixel_error_response(exc)

    def api_pixel_accounts_bulk_update(target_id: str):
        rejected = pixel_target_rejected(target_id)
        if rejected is not None:
            return rejected
        if context.pixel_client is None:
            return pixel_unavailable()
        try:
            data = request_json_object()
            result = context.pixel_client.share_accounts(target_id, account_ids_from(data))
            return pixel_json_result(result)
        except Exception as exc:
            return pixel_error_response(exc)

    def api_pixel_relogin(target_id: str):
        rejected = pixel_target_rejected(target_id)
        if rejected is not None:
            return rejected
        if context.pixel_client is None:
            return pixel_unavailable()
        try:
            return pixel_json_result(context.pixel_client.relogin(target_id))
        except Exception as exc:
            return pixel_error_response(exc)

    def api_pixel_share_all():
        if context.pixel_client is None:
            return pixel_unavailable()
        try:
            requested = target_ids_from(request_json_object())
            requested = list(_PIXEL_AUTO_TARGET_IDS) if requested is None else requested
            invalid = [
                target_id
                for target_id in requested
                if target_id not in _PIXEL_AUTO_TARGET_IDS
            ]
            if invalid:
                return module.jsonify(
                    ok=False,
                    error="一键共享只能选择 pixel-2 至 pixel-7",
                ), 400
            targets = list(requested)
            if not targets:
                return module.jsonify(
                    ok=False,
                    error="一键共享没有可执行的自动上传目标",
                ), 400
            return pixel_json_result(context.pixel_client.share_all(targets))
        except Exception as exc:
            return pixel_error_response(exc)

    def api_pixel_upload_records():
        if context.pixel_upload_queue is None:
            return pixel_unavailable(queue=True)
        try:
            return module.jsonify(
                ok=True,
                records=context.pixel_upload_queue.records(),
            )
        except Exception as exc:
            return pixel_error_response(exc)

    def api_pixel_upload_retry(record_id: str):
        if context.pixel_upload_queue is None:
            return pixel_unavailable(queue=True)
        try:
            target_ids = target_ids_from(request_json_object())
            if target_ids is not None and any(
                target_id not in _PIXEL_AUTO_TARGET_IDS for target_id in target_ids
            ):
                return module.jsonify(
                    ok=False,
                    error="Pixel 重传只能选择 pixel-2 至 pixel-7",
                ), 400
            record = context.pixel_upload_queue.retry(record_id, target_ids)
            return module.jsonify(ok=True, record=record)
        except Exception as exc:
            return pixel_error_response(exc)

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

    def api_notification_email_test():
        try:
            data = module.request.get_json(silent=True) or {}
            if not isinstance(data, dict):
                return module.jsonify(ok=False, error="配置必须是 JSON 对象"), 400
            result = context.test_email_notification(data)
            return module.jsonify(ok=True, notification=result, state=public_state())
        except ValueError as exc:
            safe = context.safe_runtime_error(exc)
            return module.jsonify(ok=False, error=safe, state=public_state()), 400
        except Exception:
            logs.add("测试邮件通知发送失败，请检查 SMTP 配置和网络", "error")
            return module.jsonify(
                ok=False,
                error="测试通知发送失败，请检查发件账号、授权码、收件地址和网络",
                state=public_state(),
            ), 502

    routes = (
        ("/mailboxes", "mailbox_manager", mailbox_manager, ["GET"]),
        ("/url-test", "mailbox_url_test_page", mailbox_url_test_page, ["GET"]),
        ("/accounts", "account_manager", mailbox_manager, ["GET"]),
        ("/settings", "settings_page", mailbox_manager, ["GET"]),
        ("/api/mailboxes", "api_mailboxes", api_mailboxes, ["GET"]),
        ("/api/mailboxes/import", "api_mailboxes_import", api_mailboxes_import, ["POST"]),
        ("/api/mailboxes/delete", "api_mailboxes_delete", api_mailboxes_delete, ["POST"]),
        ("/api/mailboxes/restore", "api_mailboxes_restore", api_mailboxes_restore, ["POST"]),
        ("/api/mailboxes/latest-code", "api_mailboxes_latest_code", api_mailboxes_latest_code, ["POST"]),
        ("/api/mailboxes/password", "api_mailboxes_password", api_mailboxes_password, ["POST"]),
        ("/api/mailboxes/totp", "api_mailboxes_totp", api_mailboxes_totp, ["POST"]),
        ("/api/mailbox-url-test", "api_mailbox_url_test", api_mailbox_url_test, ["POST"]),
        ("/api/mailboxes/sub2-test", "api_mailboxes_sub2_test", api_mailboxes_sub2_test, ["POST"]),
        ("/api/mailboxes/quota", "api_mailboxes_quota", api_mailboxes_quota, ["POST"]),
        ("/api/mailboxes/pixel-retry", "api_mailboxes_pixel_retry", api_mailboxes_pixel_retry, ["POST"]),
        ("/api/mailboxes/sub2-export", "api_mailboxes_sub2_export", api_mailboxes_sub2_export, ["POST"]),
        ("/api/pixel/targets", "api_pixel_targets", api_pixel_targets, ["GET"]),
        (
            "/api/pixel/targets/<target_id>/accounts",
            "api_pixel_accounts",
            api_pixel_accounts,
            ["GET"],
        ),
        (
            "/api/pixel/targets/<target_id>/accounts/bulk-test",
            "api_pixel_accounts_bulk_test",
            api_pixel_accounts_bulk_test,
            ["POST"],
        ),
        (
            "/api/pixel/targets/<target_id>/accounts/bulk-update",
            "api_pixel_accounts_bulk_update",
            api_pixel_accounts_bulk_update,
            ["POST"],
        ),
        (
            "/api/pixel/targets/<target_id>/relogin",
            "api_pixel_relogin",
            api_pixel_relogin,
            ["POST"],
        ),
        ("/api/pixel/share-all", "api_pixel_share_all", api_pixel_share_all, ["POST"]),
        ("/api/pixel/upload-records", "api_pixel_upload_records", api_pixel_upload_records, ["GET"]),
        (
            "/api/pixel/upload-records/<record_id>/retry",
            "api_pixel_upload_retry",
            api_pixel_upload_retry,
            ["POST"],
        ),
        ("/api/local-config", "api_local_config", api_local_config, ["GET"]),
        ("/api/local-config/export", "api_local_config_export", api_local_config_export, ["POST"]),
        ("/api/local-config/import", "api_local_config_import", api_local_config_import, ["POST"]),
        ("/api/local-config/secret", "api_local_config_secret", api_local_config_secret, ["POST"]),
        ("/api/notifications/email/test", "api_notification_email_test", api_notification_email_test, ["POST"]),
    )
    for rule, endpoint, view_func, methods in routes:
        if endpoint not in app.view_functions:
            app.add_url_rule(rule, endpoint, view_func, methods=methods)

    app._gptphone_mac_patched = True
    return app
