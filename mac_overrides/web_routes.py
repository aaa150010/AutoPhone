"""Flask route assembly for the recovered web GUI."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
import ipaddress
from pathlib import Path
import threading
import time
from typing import Any, Callable
import urllib.parse
import uuid

try:
    from . import pixel_route_runtime as _pixel_route_runtime_ext
except ImportError:  # Loaded as a top-level runtime override by web_gui.py.
    import pixel_route_runtime as _pixel_route_runtime_ext

try:
    from .mailbox_batch_operations import MailboxBatchRouteController
except ImportError:  # Loaded as a top-level runtime override by web_gui.py.
    from mailbox_batch_operations import MailboxBatchRouteController

try:
    from .mailbox_mutation_routes import MailboxMutationRouteController
except ImportError:  # Loaded as a top-level runtime override by web_gui.py.
    from mailbox_mutation_routes import MailboxMutationRouteController

try:
    from .mailbox_state_runtime import mark_mailboxes_unavailable
except ImportError:  # Loaded as a top-level runtime override by web_gui.py.
    from mailbox_state_runtime import mark_mailboxes_unavailable

try:
    from .runtime_info_routes import RuntimeInfoRouteController
except ImportError:  # Loaded as a top-level runtime override by web_gui.py.
    from runtime_info_routes import RuntimeInfoRouteController

_PIXEL_AUTO_TARGET_IDS = tuple(f"pixel-{index}" for index in range(2, 8))
_SHA256_HEX_CHARACTERS = frozenset("0123456789abcdef")
_SMS_BALANCE_CONFIG_KEYS = (
    "sms_provider_pools",
    "sms_provider",
    "sms_api_keys",
    "sms_api_key",
    "service",
    "sms_min_price",
    "max_price",
    "proxy",
    "proxy_scope",
)


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
        if (
            len(row_id) != 64
            or any(character not in _SHA256_HEX_CHARACTERS for character in row_id)
            or line_no <= 0
        ):
            return None
        binding = (row_id, line_no)
        if binding in seen:
            continue
        seen.add(binding)
        normalized.append({"row_id": row_id, "line_no": line_no})
    return normalized


def _normalize_upload_targets(value: Any) -> dict[str, bool] | None:
    if value is None:
        return {"pixel": False, "nv": False}
    if not isinstance(value, Mapping):
        return None
    return {
        "pixel": value.get("pixel") is True,
        "nv": value.get("nv") is True,
    }


def _is_secure_nv_url(value: Any) -> bool:
    try:
        parsed = urllib.parse.urlsplit(str(value or "").strip())
        hostname = parsed.hostname
        parsed.port
    except ValueError:
        return False
    if (
        parsed.scheme.lower() not in {"http", "https"}
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        return False
    normalized_host = hostname.lower().rstrip(".")
    is_loopback = normalized_host == "localhost"
    if not is_loopback:
        try:
            is_loopback = ipaddress.ip_address(normalized_host).is_loopback
        except ValueError:
            is_loopback = False
    return parsed.scheme.lower() == "https" or is_loopback


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
    nv_upload_queue: Any | None = None
    batch_upload_coordinator: Any | None = None
    run_batch_manifest: Any | None = None
    pixel_payload_builder: Callable[[Mapping[str, Any]], dict[str, Any]] | None = None
    mailbox_url_test_factory: Callable[[], Any] | None = None
    query_sms_balances: Callable[[dict[str, Any]], list[dict[str, Any]]] | None = None
    online_mailbox_client_factory: Callable[[str, str], Any] | None = None


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
    if context.nv_upload_queue is not None:
        context.nv_upload_queue.log_fn = logs.add
    if context.batch_upload_coordinator is not None:
        context.batch_upload_coordinator.log_fn = logs.add
    if context.run_batch_manifest is not None:
        context.run_batch_manifest.log_fn = logs.add
    pixel_target_cache: dict[str, Any] = {
        "expires_at": 0.0,
        "targets": [],
    }
    pixel_target_cache_lock = threading.Lock()
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

            upload_targets = _normalize_upload_targets(data.pop("upload_targets", None))
            if upload_targets is None:
                return module.jsonify(ok=False, error="上传目标参数必须是 JSON 对象"), 400
            if upload_targets["pixel"] and context.pixel_upload_queue is None:
                return module.jsonify(ok=False, error="Pixel 上传服务尚未启用"), 503
            if upload_targets["nv"]:
                request_nv_import = data.get("nv_import")
                request_has_nv_config = isinstance(request_nv_import, Mapping) and any(
                    key in request_nv_import for key in ("endpoint", "schema_url", "api_key")
                )
                prospective = context.local_config_from_runtime(
                    data,
                    context.read_local_config(),
                )
                nv_import = prospective.get("nv_import") if isinstance(prospective, Mapping) else None
                nv_import = nv_import if isinstance(nv_import, Mapping) else {}
                endpoint = str(nv_import.get("endpoint") or "").strip()
                schema_url = str(nv_import.get("schema_url") or "").strip()
                api_key = str(nv_import.get("api_key") or "").strip()
                configured_from_request = bool(
                    context.nv_upload_queue is not None
                    and _is_secure_nv_url(endpoint)
                    and (not schema_url or _is_secure_nv_url(schema_url))
                    and api_key
                    and api_key != "********"
                )
                nv_client = getattr(context.nv_upload_queue, "client", None)
                configured = configured_from_request if request_has_nv_config else bool(
                    context.nv_upload_queue is not None
                    and callable(getattr(nv_client, "configured", None))
                    and nv_client.configured()
                )
                if not configured:
                    return module.jsonify(
                        ok=False,
                        code="nv_configuration_invalid",
                        node_code="nv_import",
                        node_label="NV 账号导入",
                        error=(
                            "NV 账号导入 [NV 账号导入/nv_import]：地址必须使用 HTTPS"
                            "（仅本机回环地址可使用 HTTP），且 API Key 必须已配置"
                        ),
                    ), 400

            run_mailbox_rows = _normalize_run_mailbox_rows(data.pop("run_mailbox_rows", None))
            if run_mailbox_rows is None:
                return module.jsonify(
                    ok=False,
                    error="本次运行的邮箱行绑定参数无效",
                ), 400
            if run_mailbox_rows:
                persisted_config = store.load()
                if "target_count" in persisted_config:
                    data["target_count"] = persisted_config["target_count"]
                else:
                    data.pop("target_count", None)

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
            run_config["_gptphone_upload_targets"] = upload_targets
            if run_mailbox_rows:
                run_config["target_count"] = len(run_mailbox_rows)
                run_config["_gptphone_run_mailbox_rows"] = run_mailbox_rows
            importer.start(run_config)
            if context.batch_upload_coordinator is not None and any(upload_targets.values()):
                try:
                    context.batch_upload_coordinator.begin(importer, run_config)
                except Exception as exc:
                    logs.add(
                        "批次上传清单创建失败 [批次上传协调/batch_upload_manifest]："
                        f"{context.safe_runtime_error(exc)}；注册任务继续运行",
                        "error",
                    )
            batch = (
                context.run_batch_manifest.get(run_config["batch_id"])
                if context.run_batch_manifest is not None
                else None
            )
            return module.jsonify(
                ok=True,
                batch_id=run_config["batch_id"],
                batch=batch,
                upload_targets=upload_targets,
                state=public_state(),
            )
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

    runtime_info_routes = RuntimeInfoRouteController(
        module=module,
        context=context,
        mailbox_admin=mailbox_admin,
        importer=importer,
        logs=logs,
    )
    api_mailbox_url_test = runtime_info_routes.mailbox_url_test

    mailbox_batch_routes = MailboxBatchRouteController(
        module=module,
        mailbox_admin=mailbox_admin,
        public_state=public_state,
        logs=logs,
    )
    app.extensions["gptphone_mailbox_batch_operations"] = mailbox_batch_routes.manager
    api_mailboxes = mailbox_batch_routes.mailboxes
    mailbox_mutation_routes = MailboxMutationRouteController(
        module=module,
        mailbox_admin=mailbox_admin,
        public_state=public_state,
        logs=logs,
        safe_error=context.safe_runtime_error,
        unavailable_action=lambda admin, payload: mark_mailboxes_unavailable(
            admin,
            payload,
        ),
    )

    def api_mailboxes_website_import():
        node_code = "online_mailbox_upload"
        node_label = "网站邮箱上传"

        def failure(message: str, code: str, status: int, provider_status: Any = None):
            public_message = f"网站邮箱上传 [{node_label}/{node_code}]：{message}"
            logs.add(public_message, "error")
            payload = {
                "ok": False,
                "node_code": node_code,
                "node_label": node_label,
                "error_code": code,
                "error": public_message,
            }
            if provider_status is not None:
                payload["provider_status"] = provider_status
            return module.jsonify(payload), status

        if context.online_mailbox_client_factory is None:
            return failure("服务尚未配置", "online_mailbox_not_configured", 503)
        try:
            local = context.read_local_config()
            config = local.get("online_mailbox") if isinstance(local, Mapping) else {}
            config = config if isinstance(config, Mapping) else {}
            base_url = str(config.get("base_url") or "").strip()
            api_token = str(config.get("api_token") or "").strip()
            if not api_token or api_token == "********":
                return failure(
                    "尚未配置 API 密钥，请先在平台集成中保存",
                    "online_mailbox_token_missing",
                    400,
                )
            snapshotter = getattr(mailbox_admin, "online_mailbox_snapshot", None)
            if not callable(snapshotter):
                return failure("本机邮箱快照不可用", "online_mailbox_snapshot_unavailable", 503)
            snapshot = snapshotter()
            items = snapshot.get("items") if isinstance(snapshot, Mapping) else []
            if not items:
                return failure(
                    "本机没有带取件 URL 的可上传邮箱",
                    "online_mailbox_items_empty",
                    400,
                )
            client = context.online_mailbox_client_factory(base_url, api_token)
            result = client.upload(items, batch_id=str(uuid.uuid4()))
            response = {
                "ok": True,
                "batch_id": str(result.get("batch_id") or ""),
                "submitted": int(result.get("submitted") or 0),
                "created": int(result.get("created") or 0),
                "updated": int(result.get("updated") or 0),
                "duplicates": int(result.get("duplicates") or 0),
                "rejected": int(result.get("rejected") or 0),
                "skipped": int(snapshot.get("skipped") or 0),
                "local_duplicates": int(snapshot.get("local_duplicates") or 0),
                "manager_url": str(result.get("manager_url") or ""),
            }
            logs.add(
                "网站邮箱上传完成: "
                f"新增 {response['created']}，更新 {response['updated']}，"
                f"重复 {response['duplicates']}，跳过 {response['skipped']}",
                "success",
            )
            return module.jsonify(response)
        except Exception as exc:
            public = str(getattr(exc, "public_message", "") or "服务端未返回错误详情")
            code = str(getattr(exc, "code", "") or "online_mailbox_upload_failed")
            try:
                status = int(getattr(exc, "status_code", 502) or 502)
            except (TypeError, ValueError):
                status = 502
            if status < 400 or status > 599:
                status = 502
            provider_status = getattr(exc, "provider_status", None)
            return failure(public, code, status, provider_status)

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
            return module.jsonify(ok=False, error="读取临时 2FA 验证码失败"), 500

    api_mailboxes_url = runtime_info_routes.mailbox_url
    api_runtime_task_mailbox_url = runtime_info_routes.runtime_task_mailbox_url

    def api_mailboxes_relogin():
        if not context.lifecycle_lock.acquire(blocking=False):
            return busy_response("另一个启动请求正在处理中")
        try:
            if importer.status(settings()).get("running"):
                return module.jsonify(
                    ok=False,
                    code="run_already_active",
                    error="已有任务运行中，请先停止并等待任务结束",
                    state=public_state(),
                ), 409
            data = module.request.get_json(silent=True) or {}
            if not isinstance(data, dict):
                return module.jsonify(ok=False, code="relogin_rows_invalid", error="请求必须是 JSON 对象"), 400
            resolver = getattr(mailbox_admin, "resolve_relogin_rows", None)
            if not callable(resolver):
                return module.jsonify(
                    ok=False,
                    code="relogin_not_configured",
                    error="无手机号重登尚未配置",
                ), 503
            selected = resolver(data)
            if not isinstance(selected, Mapping):
                return module.jsonify(
                    ok=False,
                    code="relogin_resolution_failed",
                    error="重登邮箱校验失败：未返回可用诊断",
                ), 502
            if not selected.get("ok"):
                code = str(selected.get("code") or "")
                status = 409 if code in {"mailbox_rows_stale", "relogin_not_required"} else 400
                return module.jsonify(dict(selected)), status

            rows = [dict(item) for item in selected.get("items") or [] if isinstance(item, Mapping)]
            if not rows:
                return module.jsonify(
                    ok=False,
                    code="relogin_rows_required",
                    error="请先勾选需要重登的 401/404 邮箱",
                ), 400
            run_config = dict(store.load() or {})
            batch_started_at = int(time.time())
            run_config.update(
                run_mode="relogin",
                target_count=len(rows),
                batch_started_at=batch_started_at,
                batch_id=(
                    f"relogin-{time.strftime('%Y%m%d-%H%M%S', time.localtime(batch_started_at))}-"
                    f"{uuid.uuid4().hex[:6]}"
                ),
                _gptphone_upload_targets={"pixel": False, "nv": False},
                _gptphone_relogin_rows=rows,
                _gptphone_run_mailbox_rows=[
                    {"row_id": row["row_id"], "line_no": row["line_no"]}
                    for row in rows
                ],
            )
            context.sms_cost_ledger.clear()
            importer.start(run_config)
            logs.add(
                f"无手机号重登任务已启动: {len(rows)} 个邮箱，仅原位更新 SUB2",
                "success",
            )
            return module.jsonify(
                ok=True,
                run_mode="relogin",
                batch_id=run_config["batch_id"],
                batch=(
                    context.run_batch_manifest.get(run_config["batch_id"])
                    if context.run_batch_manifest is not None
                    else None
                ),
                started=len(rows),
                mailboxes=mailbox_admin.list_mailboxes(),
                state=public_state(),
            )
        except ValueError as exc:
            safe = context.safe_runtime_error(exc)
            return module.jsonify(ok=False, code="relogin_start_failed", error=safe, state=public_state()), 400
        except Exception as exc:
            safe = context.safe_runtime_error(exc)
            logs.add(f"无手机号重登启动失败: {safe}", "error")
            return module.jsonify(
                ok=False,
                code="relogin_start_failed",
                error=f"重登任务启动失败: {safe}",
                state=public_state(),
            ), 500
        finally:
            context.lifecycle_lock.release()

    api_mailboxes_openai_test = mailbox_batch_routes.openai_test
    # Keep the original URL as a compatibility alias for existing clients.
    api_mailboxes_sub2_test = mailbox_batch_routes.openai_test
    api_mailboxes_quota = mailbox_batch_routes.quota

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

    def nv_error_response(exc: Exception):
        public_message = str(getattr(exc, "public_message", "") or "")
        failure_builder = getattr(exc, "failure", None)
        failure = failure_builder() if callable(failure_builder) else None
        try:
            status = int(getattr(exc, "status_code", 500) or 500)
        except (TypeError, ValueError):
            status = 500
        if not 400 <= status <= 599:
            status = 500
        if public_message:
            payload = {
                "ok": False,
                "node_code": "nv_import",
                "node_label": "NV 账号导入",
                "error": public_message,
            }
            if isinstance(failure, Mapping):
                payload["failure"] = dict(failure)
                payload["code"] = str(failure.get("error_code") or "nv_import_failed")
            return module.jsonify(payload), status
        logs.add("NV 上传记录操作失败 [NV 账号导入/nv_import]：未返回可用诊断", "error")
        return module.jsonify(
            ok=False,
            code="nv_import_failed",
            node_code="nv_import",
            node_label="NV 账号导入",
            error="NV 账号导入失败：未返回可用诊断",
        ), 500

    def pixel_json_result(value: Any, **extra: Any):
        payload = dict(value) if isinstance(value, Mapping) else {}
        payload.update(extra)
        payload.setdefault("ok", True)
        return module.jsonify(payload)

    def request_json_object() -> dict[str, Any]:
        value = module.request.get_json(silent=True) or {}
        return dict(value) if isinstance(value, Mapping) else {}

    account_ids_from = _pixel_route_runtime_ext.account_ids_from
    target_ids_from = _pixel_route_runtime_ext.target_ids_from

    def pixel_target_rejected(target_id: Any):
        normalized = str(target_id or "").strip()
        if normalized in _PIXEL_AUTO_TARGET_IDS:
            return None
        return module.jsonify(
            ok=False,
            error="Pixel 账号管理：该目标未开放（仅支持 pixel-2 至 pixel-7）",
        ), 404

    def pixel_target_totals() -> tuple[list[dict[str, Any]], str]:
        now = time.monotonic()
        with pixel_target_cache_lock:
            if pixel_target_cache["targets"] and now < float(pixel_target_cache["expires_at"]):
                return [dict(item) for item in pixel_target_cache["targets"]], ""
        if context.pixel_client is None:
            return [
                {"target_id": target_id, "account_count": None}
                for target_id in _PIXEL_AUTO_TARGET_IDS
            ], "Pixel 管理服务尚未配置"
        try:
            payload = context.pixel_client.targets()
            source = payload.get("data") if isinstance(payload, Mapping) and isinstance(payload.get("data"), Mapping) else payload
            raw_targets = source.get("targets") if isinstance(source, Mapping) else []
            by_id: dict[str, Mapping[str, Any]] = {}
            for item in raw_targets if isinstance(raw_targets, list) else []:
                if not isinstance(item, Mapping):
                    continue
                target_id = str(
                    item.get("id") or item.get("target_id") or item.get("targetId") or ""
                ).strip()
                if target_id in _PIXEL_AUTO_TARGET_IDS:
                    by_id[target_id] = item
            targets = []
            for target_id in _PIXEL_AUTO_TARGET_IDS:
                item = by_id.get(target_id, {})
                raw_count = None
                for key in ("account_count", "accountCount", "accounts_count", "accountsCount", "total"):
                    if item.get(key) is not None:
                        raw_count = item.get(key)
                        break
                if raw_count is None and isinstance(item.get("stats"), Mapping):
                    raw_count = item["stats"].get("total")
                count = max(0, _safe_int(raw_count, 0)) if raw_count is not None else None
                targets.append({"target_id": target_id, "account_count": count})
            with pixel_target_cache_lock:
                pixel_target_cache["targets"] = [dict(item) for item in targets]
                pixel_target_cache["expires_at"] = now + 30.0
            return targets, ""
        except Exception as exc:
            public_message = str(getattr(exc, "public_message", "") or "").strip()
            with pixel_target_cache_lock:
                cached = [dict(item) for item in pixel_target_cache["targets"]]
            if not cached:
                cached = [
                    {"target_id": target_id, "account_count": None}
                    for target_id in _PIXEL_AUTO_TARGET_IDS
                ]
            return cached, public_message or "Pixel 平台账号总数暂时无法读取"

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

    def api_pixel_overview():
        if context.pixel_upload_queue is None:
            return pixel_unavailable(queue=True)
        try:
            payload = dict(context.pixel_upload_queue.overview())
            targets, target_error = pixel_target_totals()
            payload["targets"] = targets
            payload["target_error"] = target_error
            return pixel_json_result(payload)
        except Exception as exc:
            return pixel_error_response(exc)

    def api_pixel_upload_batches():
        if context.pixel_upload_queue is None:
            return pixel_unavailable(queue=True)
        try:
            return pixel_json_result(
                context.pixel_upload_queue.batches(
                    page=module.request.args.get("page", 1),
                    page_size=module.request.args.get("page_size", 20),
                )
            )
        except Exception as exc:
            return pixel_error_response(exc)

    def api_pixel_batch_records(batch_id: str):
        if context.pixel_upload_queue is None:
            return pixel_unavailable(queue=True)
        try:
            return pixel_json_result(
                context.pixel_upload_queue.batch_records(
                    batch_id,
                    page=module.request.args.get("page", 1),
                    page_size=module.request.args.get("page_size", 50),
                    status=module.request.args.get("status", ""),
                )
            )
        except Exception as exc:
            return pixel_error_response(exc)

    def api_pixel_batch_retry(batch_id: str):
        if context.pixel_upload_queue is None:
            return pixel_unavailable(queue=True)
        try:
            summary = _pixel_route_runtime_ext.retry_batch_targets(
                context.pixel_upload_queue,
                batch_id,
                target_ids_from(request_json_object()),
                allowed_targets=_PIXEL_AUTO_TARGET_IDS,
                log_fn=logs.add,
            )
            return module.jsonify(ok=True, **summary)
        except Exception as exc:
            payload, status = _pixel_route_runtime_ext.batch_retry_failure(exc)
            logs.add(f"[{payload['node_label']}/{payload['node_code']}] {payload['code']}", "error")
            return module.jsonify(**payload), status

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

    def api_nv_overview():
        if context.nv_upload_queue is None:
            return module.jsonify(ok=False, error="NV 上传队列尚未配置"), 503
        try:
            return module.jsonify(ok=True, **context.nv_upload_queue.overview())
        except Exception as exc:
            return nv_error_response(exc)

    def api_nv_upload_records():
        if context.nv_upload_queue is None:
            return module.jsonify(ok=False, error="NV 上传队列尚未配置"), 503
        try:
            records = context.nv_upload_queue.records()
            page = max(1, _safe_int(module.request.args.get("page"), 1))
            page_size = min(max(1, _safe_int(module.request.args.get("page_size"), 50)), 100)
            total = len(records)
            pages = max(1, (total + page_size - 1) // page_size)
            page = min(page, pages)
            start = (page - 1) * page_size
            return module.jsonify(
                ok=True,
                records=records[start:start + page_size],
                total=total,
                page=page,
                page_size=page_size,
                pages=pages,
                revision=_safe_int(context.nv_upload_queue.overview().get("revision"), 0),
            )
        except Exception as exc:
            return nv_error_response(exc)

    def api_nv_upload_batches():
        if context.nv_upload_queue is None:
            return module.jsonify(ok=False, error="NV 上传队列尚未配置"), 503
        try:
            items = context.nv_upload_queue.batches()
            page = max(1, _safe_int(module.request.args.get("page"), 1))
            page_size = min(max(1, _safe_int(module.request.args.get("page_size"), 20)), 100)
            total = len(items)
            pages = max(1, (total + page_size - 1) // page_size)
            page = min(page, pages)
            start = (page - 1) * page_size
            return module.jsonify(
                ok=True,
                items=items[start:start + page_size],
                total=total,
                page=page,
                page_size=page_size,
                pages=pages,
                revision=_safe_int(context.nv_upload_queue.overview().get("revision"), 0),
            )
        except Exception as exc:
            return nv_error_response(exc)

    def api_nv_upload_retry(record_id: str):
        if context.nv_upload_queue is None:
            return module.jsonify(ok=False, error="NV 上传队列尚未配置"), 503
        try:
            return module.jsonify(ok=True, record=context.nv_upload_queue.retry(record_id))
        except Exception as exc:
            return nv_error_response(exc)

    def api_batch_upload_manifests():
        if context.batch_upload_coordinator is None:
            return module.jsonify(ok=True, records=[])
        try:
            limit = min(max(1, _safe_int(module.request.args.get("limit"), 100)), 500)
            records = context.batch_upload_coordinator.records()
            return module.jsonify(ok=True, records=records[:limit], total=len(records))
        except Exception as exc:
            logs.add("批次上传清单查询失败 [批次上传协调/batch_upload_manifest]", "error")
            return module.jsonify(ok=False, error=context.safe_runtime_error(exc)), 500

    api_run_batches = runtime_info_routes.run_batches
    api_run_batch = runtime_info_routes.run_batch

    def api_batch_upload_manifest_retry(batch_id: str):
        if context.batch_upload_coordinator is None:
            return module.jsonify(
                ok=False,
                node_code="batch_upload_manifest",
                node_label="批次上传协调",
                error_code="batch_upload_coordinator_unavailable",
                error="批次上传协调 [批次上传协调/batch_upload_manifest]：服务尚未启用",
            ), 503
        data = module.request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return module.jsonify(ok=False, error="批次上传重试参数必须是 JSON 对象"), 400
        if set(data) != {"platform"}:
            return module.jsonify(ok=False, error="批次上传重试只接受 platform 参数"), 400
        platform = data.get("platform")
        if platform not in {"pixel", "nv"}:
            return module.jsonify(ok=False, error="批次上传重试平台必须是 pixel 或 nv"), 400
        try:
            manifest = context.batch_upload_coordinator.retry(batch_id, platform)
            return module.jsonify(ok=True, manifest=manifest)
        except KeyError:
            return module.jsonify(
                ok=False,
                node_code="batch_upload_manifest",
                node_label="批次上传协调",
                error_code="batch_upload_manifest_not_found",
                error="批次上传协调 [批次上传协调/batch_upload_manifest]：批次不存在",
            ), 404
        except ValueError as exc:
            return module.jsonify(
                ok=False,
                node_code="batch_upload_manifest",
                node_label="批次上传协调",
                error_code="batch_upload_retry_unavailable",
                error=(
                    "批次上传协调 [批次上传协调/batch_upload_manifest]："
                    f"{context.safe_runtime_error(exc)}"
                ),
            ), 409
        except Exception:
            logs.add("批次上传重试失败 [批次上传协调/batch_upload_manifest]", "error")
            return module.jsonify(
                ok=False,
                node_code="batch_upload_manifest",
                node_label="批次上传协调",
                error_code="batch_upload_retry_failed",
                error="批次上传协调 [批次上传协调/batch_upload_manifest]：未返回可用诊断",
            ), 500

    def api_local_config():
        return module.jsonify(
            ok=True,
            config=context.masked_local_config(context.read_local_config()),
        )

    def api_sms_balances():
        if context.query_sms_balances is None:
            return module.jsonify(
                ok=False,
                node_code="sms_balance_query",
                node_label="接码余额",
                error_code="sms_balance_query_unavailable",
                error="接码余额查询 [接码余额/sms_balance_query]：服务尚未启用",
            ), 503
        data = module.request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return module.jsonify(
                ok=False,
                node_code="sms_balance_query",
                node_label="接码余额",
                error_code="invalid_request",
                error="接码余额查询 [接码余额/sms_balance_query]：配置必须是 JSON 对象",
            ), 400
        try:
            local = context.read_local_config()
            config = {
                key: data[key] if key in data else local[key]
                for key in _SMS_BALANCE_CONFIG_KEYS
                if key in data or key in local
            }
            statuses = context.query_sms_balances(config)
            return module.jsonify(
                ok=True,
                queried_at=int(time.time()),
                sms_key_statuses=statuses,
            )
        except ValueError as exc:
            safe = context.safe_runtime_error(exc)
            return module.jsonify(
                ok=False,
                node_code="sms_balance_query",
                node_label="接码余额",
                error_code="sms_balance_query_failed",
                error=f"接码余额查询 [接码余额/sms_balance_query]：{safe}",
            ), 400
        except Exception:
            return module.jsonify(
                ok=False,
                node_code="sms_balance_query",
                node_label="接码余额",
                error_code="sms_balance_query_failed",
                error="接码余额查询 [接码余额/sms_balance_query]：平台请求失败，请检查 Key、代理和网络",
            ), 502

    def api_local_config_export():
        try:
            data = module.request.get_json(silent=True) or {}
            download = bool(data.pop("download", False)) if isinstance(data, dict) else False
            config = context.local_config_from_runtime(data, context.read_local_config())
            config = dict(config)
            if isinstance(config.get("nv_import"), Mapping):
                nv_import = dict(config["nv_import"])
                nv_import.pop("api_key", None)
                config["nv_import"] = nv_import
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
        ("/api/mailboxes/import", "api_mailboxes_import", mailbox_mutation_routes.import_mailboxes, ["POST"]),
        ("/api/mailboxes/delete", "api_mailboxes_delete", mailbox_mutation_routes.delete_mailboxes, ["POST"]),
        ("/api/mailboxes/restore", "api_mailboxes_restore", mailbox_mutation_routes.restore_mailboxes, ["POST"]),
        ("/api/mailboxes/unavailable", "api_mailboxes_unavailable", mailbox_mutation_routes.unavailable_mailboxes, ["POST"]),
        ("/api/mailboxes/website-import", "api_mailboxes_website_import", api_mailboxes_website_import, ["POST"]),
        ("/api/mailboxes/latest-code", "api_mailboxes_latest_code", api_mailboxes_latest_code, ["POST"]),
        ("/api/mailboxes/password", "api_mailboxes_password", api_mailboxes_password, ["POST"]),
        ("/api/mailboxes/totp", "api_mailboxes_totp", api_mailboxes_totp, ["POST"]),
        ("/api/mailboxes/url", "api_mailboxes_url", api_mailboxes_url, ["POST"]),
        (
            "/api/runtime/tasks/mailbox-url",
            "api_runtime_task_mailbox_url",
            api_runtime_task_mailbox_url,
            ["POST"],
        ),
        ("/api/mailboxes/relogin", "api_mailboxes_relogin", api_mailboxes_relogin, ["POST"]),
        ("/api/mailbox-url-test", "api_mailbox_url_test", api_mailbox_url_test, ["POST"]),
        ("/api/mailboxes/sub2-test", "api_mailboxes_sub2_test", api_mailboxes_sub2_test, ["POST"]),
        ("/api/mailboxes/openai-test", "api_mailboxes_openai_test", api_mailboxes_openai_test, ["POST"]),
        ("/api/mailboxes/quota", "api_mailboxes_quota", api_mailboxes_quota, ["POST"]),
        ("/api/run-batches", "api_run_batches", api_run_batches, ["GET"]),
        (
            "/api/run-batches/<batch_id>",
            "api_run_batch",
            api_run_batch,
            ["GET"],
        ),
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
        ("/api/pixel/overview", "api_pixel_overview", api_pixel_overview, ["GET"]),
        ("/api/pixel/upload-batches", "api_pixel_upload_batches", api_pixel_upload_batches, ["GET"]),
        (
            "/api/pixel/upload-batches/<batch_id>/records",
            "api_pixel_batch_records",
            api_pixel_batch_records,
            ["GET"],
        ),
        (
            "/api/pixel/upload-batches/<batch_id>/retry",
            "api_pixel_batch_retry",
            api_pixel_batch_retry,
            ["POST"],
        ),
        ("/api/pixel/upload-records", "api_pixel_upload_records", api_pixel_upload_records, ["GET"]),
        (
            "/api/pixel/upload-records/<record_id>/retry",
            "api_pixel_upload_retry",
            api_pixel_upload_retry,
            ["POST"],
        ),
        ("/api/nv/overview", "api_nv_overview", api_nv_overview, ["GET"]),
        ("/api/nv/upload-batches", "api_nv_upload_batches", api_nv_upload_batches, ["GET"]),
        ("/api/nv/upload-records", "api_nv_upload_records", api_nv_upload_records, ["GET"]),
        (
            "/api/nv/upload-records/<record_id>/retry",
            "api_nv_upload_retry",
            api_nv_upload_retry,
            ["POST"],
        ),
        ("/api/upload-manifests", "api_batch_upload_manifests", api_batch_upload_manifests, ["GET"]),
        (
            "/api/upload-manifests/<batch_id>/retry",
            "api_batch_upload_manifest_retry",
            api_batch_upload_manifest_retry,
            ["POST"],
        ),
        ("/api/local-config", "api_local_config", api_local_config, ["GET"]),
        ("/api/sms/balances", "api_sms_balances", api_sms_balances, ["POST"]),
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
