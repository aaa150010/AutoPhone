"""Flask route assembly for the recovered web GUI."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import time
import threading
from typing import Any, Callable
import uuid

try:
    from .mailbox_batch_operations import MailboxBatchRouteController
except ImportError:  # Loaded as a top-level runtime override by web_gui.py.
    from mailbox_batch_operations import MailboxBatchRouteController

try:
    from .mailbox_mutation_routes import MailboxMutationRouteController
except ImportError:  # Loaded as a top-level runtime override by web_gui.py.
    from mailbox_mutation_routes import MailboxMutationRouteController

try:
    from .batch_identity import allocate_run_batch_id
    from .mailbox_state_runtime import mark_mailboxes_unavailable
except ImportError:  # Loaded as a top-level runtime override by web_gui.py.
    from batch_identity import allocate_run_batch_id
    from mailbox_state_runtime import mark_mailboxes_unavailable

try:
    from .local_config_routes import LocalConfigRouteController
    from .runtime_info_routes import RuntimeInfoRouteController
    from .mailbox_parser_sample_routes import MailboxParserSampleRouteController
    from .route_failures import explicit_failure_payload
    from .sms_balance_routes import SmsBalanceRouteController
except ImportError:  # Loaded as a top-level runtime override by web_gui.py.
    from local_config_routes import LocalConfigRouteController
    from runtime_info_routes import RuntimeInfoRouteController
    from mailbox_parser_sample_routes import MailboxParserSampleRouteController  # type: ignore[no-redef]
    from route_failures import explicit_failure_payload
    from sms_balance_routes import SmsBalanceRouteController

try:
    from .free_register_common import safe_log_message as _safe_free_message
    from .free_config_routes import FreeControlRouteController
    from .free_pool_routes import (
        FreePoolRouteController,
        import_free_proxies,
        signature_accepts_call,
    )
except ImportError:
    from free_register_common import safe_log_message as _safe_free_message  # type: ignore[no-redef]
    from free_config_routes import FreeControlRouteController  # type: ignore[no-redef]
    from free_pool_routes import (  # type: ignore[no-redef]
        FreePoolRouteController,
        import_free_proxies,
        signature_accepts_call,
    )

_SHA256_HEX_CHARACTERS = frozenset("0123456789abcdef")
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
    failure_secrets: Callable[[dict[str, Any]], Sequence[Any]] | None = None
    free_register_manager: Any | None = None
    free_config_store: Any | None = None
    free_data_dir: Path | None = None
    diagnostic_store: Any | None = None
    mailbox_parser_sample_store: Any | None = None
    free_mailbox_parser_sample_store: Any | None = None


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

    free_manager = context.free_register_manager
    free_config_store = context.free_config_store
    diagnostic_store = context.diagnostic_store

    def route_secrets(config: Any) -> Sequence[Any]:
        if context.failure_secrets is None or not isinstance(config, dict):
            return ()
        try:
            return context.failure_secrets(config)
        except Exception:
            return ()
    if context.run_batch_manifest is not None:
        context.run_batch_manifest.log_fn = logs.add
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
        # Vue navigation is history-based.  Register the user-facing deep
        # links explicitly so refreshing a page such as /free-mailboxes does
        # not fall through to Flask's 404 before the SPA can restore state.
        for path in (
            "/free-register",
            "/free-mailboxes",
            "/free-rebind",
            "/payment-tools",
            "/network-tools",
            "/logs",
            "/mailbox-parser-samples",
        ):
            endpoint = f"spa_deep_link_{path.strip('/').replace('-', '_')}"
            if endpoint not in app.view_functions:
                app.add_url_rule(path, endpoint, spa_index, methods=["GET"])

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
        data: dict[str, Any] = {}
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
            payload = explicit_failure_payload(
                node_code="config_save", node_label="保存运行配置", error_code="config_validation_failed",
                cause=context.safe_runtime_error(exc),
                secrets=route_secrets(data), state=public_state(), http_status=400,
            )
            return module.jsonify(payload), 400
        except Exception as exc:
            payload = explicit_failure_payload(
                node_code="config_save", node_label="保存运行配置", error_code="config_save_failed",
                cause=context.safe_runtime_error(exc),
                secrets=route_secrets(data), state=public_state(), http_status=500,
                action_hint="检查配置格式和本地数据目录后重试。",
            )
            logs.add(f"[{payload['node_label']}/{payload['node_code']}] {payload['error']}", "error")
            return module.jsonify(payload), 500
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
                status = 400 if isinstance(exc, ValueError) else 502
                payload = explicit_failure_payload(
                    node_code="sms_preflight", node_label="执行启动预检", error_code="sms_preflight_failed",
                    cause=context.safe_runtime_error(exc),
                    secrets=route_secrets(data), state=public_state(),
                    retryable=status >= 500, http_status=status,
                    action_hint="检查接码平台 Key、代理和邮箱池配置后重试。",
                )
                payload["sms_key_statuses"] = context.sms_key_pool.public_statuses()
                logs.add(f"[{payload['node_label']}/{payload['node_code']}] {payload['error']}", "error")
                return module.jsonify(payload), status
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
        failure_config: dict[str, Any] = {}
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
            failure_config = dict(data)

            run_mode = str(data.get("run_mode") or "register").strip().lower()
            if run_mode == "free_register":
                return start_free_from_request(data, legacy=True)

            data.pop("upload_targets", None)
            data.pop("nv_import", None)

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
                sms_statuses = context.preflight_sms_pool(cfg, logs=logs, importer=importer)
            except ValueError as exc:
                payload = explicit_failure_payload(
                    node_code="sms_preflight", node_label="执行启动预检", error_code="sms_preflight_failed",
                    cause=context.safe_runtime_error(exc),
                    secrets=route_secrets(failure_config), state=public_state(), http_status=400,
                    action_hint="检查接码平台 Key、代理和邮箱池配置后重试。",
                )
                return module.jsonify(payload), 400
            run_config = dict(cfg)
            batch_started_at = int(time.time())
            run_config["batch_started_at"] = batch_started_at
            run_config["batch_id"] = allocate_run_batch_id(context, batch_started_at, logs)
            run_config["_gptphone_sms_preflight_statuses"] = [
                dict(row)
                for row in sms_statuses or ()
                if isinstance(row, Mapping)
            ]
            if run_mailbox_rows:
                run_config["target_count"] = len(run_mailbox_rows)
                run_config["_gptphone_run_mailbox_rows"] = run_mailbox_rows
            importer.start(run_config)
            batch = (
                context.run_batch_manifest.get(run_config["batch_id"])
                if context.run_batch_manifest is not None
                else None
            )
            return module.jsonify(
                ok=True,
                batch_id=run_config["batch_id"],
                batch=batch,
                state=public_state(),
            )
        except ValueError as exc:
            payload = explicit_failure_payload(
                node_code="run_start", node_label="启动注册任务",
                error_code="run_start_failed", cause=context.safe_runtime_error(exc),
                secrets=route_secrets(failure_config), state=public_state(), http_status=400,
            )
            return module.jsonify(payload), 400
        except Exception as exc:
            payload = explicit_failure_payload(
                node_code="run_start", node_label="启动注册任务",
                error_code="run_start_failed",
                cause=context.safe_runtime_error(exc), secrets=route_secrets(failure_config),
                state=public_state(), retryable=True, http_status=500,
                action_hint="检查运行配置和本地服务状态后重试。",
            )
            logs.add(f"[{payload['node_label']}/{payload['node_code']}] {payload['error']}", "error")
            return module.jsonify(payload), 500
        finally:
            context.lifecycle_lock.release()

    def start():
        return start_from_request(replace_pool=True)

    app.view_functions["start"] = start

    def start_existing():
        return start_from_request(replace_pool=False)

    if "start_existing" not in app.view_functions:
        app.add_url_rule("/api/start-existing", "start_existing", start_existing, methods=["POST"])

    free_request_lock = threading.Lock()

    def free_state():
        return free_manager.public_state() if free_manager is not None else {"running": False, "tasks": [], "summary": {}}

    def free_config_public():
        return free_config_store.public() if free_config_store is not None else {}

    def free_state_failure_response(exc: Exception):
        payload = explicit_failure_payload(
            node_code="free_state_read",
            node_label="读取 Free 运行状态",
            error_code="free_state_read_failed",
            cause=_safe_free_message(exc) or "Free 运行状态不可用",
            retryable=True,
            http_status=503,
            action_hint="确认 Free 运行状态可读后再重试，本次不会修改配置或池数据。",
        )
        return module.jsonify(payload), 503

    def free_mutation_conflict(action: str):
        """Return a consistent conflict response while Free work owns its pools."""
        try:
            current_state = free_state()
        except Exception as exc:
            return free_state_failure_response(exc)
        running = bool(current_state.get("running"))
        if running:
            return module.jsonify(ok=False, error=f"Free 注册运行中，暂不能{action}，请停止当前批次后重试", state=current_state), 409
        return None

    def free_failure_response(exc: Exception, *, default_code: str, default_label: str, status: int = 400):
        try:
            current_state = free_state()
        except Exception as state_exc:
            return free_state_failure_response(state_exc)
        code = str(getattr(exc, "node_code", "") or default_code)
        label = str(getattr(exc, "node_label", "") or default_label)
        cause = _free_error_detail(exc, code)
        payload = explicit_failure_payload(
            node_code=code,
            node_label=label,
            error_code=str(getattr(exc, "error_code", "") or code),
            cause=cause,
            retryable=bool(getattr(exc, "retryable", status >= 500)),
            http_status=status,
            state=current_state,
        )
        provider_status = getattr(exc, "provider_status", None)
        if provider_status is not None:
            payload["provider_status"] = provider_status
        try:
            if free_manager is not None and callable(getattr(free_manager, "_log", None)):
                free_manager._log(f"[{label}/{code}] {payload['error']}", "error")
        except Exception:
            pass
        return module.jsonify(payload), status

    free_control_routes = FreeControlRouteController(
        module=module, manager=free_manager, config_store=free_config_store,
        state=free_state, config_public=free_config_public,
        failure_response=free_failure_response, request_lock=free_request_lock,
    )

    def save_free_config(data: Mapping[str, Any]) -> dict[str, Any]:
        if free_config_store is None:
            value = dict(data)
            value.setdefault("driver", "protocol")
            value.setdefault("concurrency", 3)
            value.setdefault("target_count", 0)
            value.setdefault("proxy_probe_url", "https://chatgpt.com/")
            value.setdefault("auto_set_2fa", True)
            return value
        return free_config_store.save(data)

    def start_free_from_request(raw: Mapping[str, Any], *, legacy: bool = False):
        if free_manager is None:
            return module.jsonify(ok=False, error="Free 注册服务尚未初始化"), 503
        if not free_request_lock.acquire(blocking=False):
            return module.jsonify(ok=False, error="Free 配置、预检或启动请求正在处理中", state=free_state()), 409
        try:
            conflict = free_mutation_conflict("启动新的 Free 批次")
            if conflict is not None:
                return conflict
            data = dict(raw)
            config_input = data.get("free_config") if isinstance(data.get("free_config"), Mapping) else data
            config_input = dict(config_input)
            if legacy:
                if "driver" not in config_input and data.get("free_driver"):
                    config_input["driver"] = data.get("free_driver")
                if "target_count" not in config_input and "free_target_count" in data:
                    config_input["target_count"] = data.get("free_target_count")
                if "concurrency" not in config_input and "free_concurrency" in data:
                    config_input["concurrency"] = data.get("free_concurrency")
            config = dict(config_input) if free_config_store is None else save_free_config(config_input)
            if free_config_store is None:
                # Test/legacy route contexts predating the isolated store only
                # have the old stub store; production never takes this branch.
                try:
                    store.save(dict(data))
                except Exception:
                    pass
            mailbox_content = str(data.get("pool_content") or data.get("free_pool_content") or "")
            proxy_content = str(data.get("proxy_content") or data.get("free_proxy_pool_content") or "")
            proxy_country = str(data.get("proxy_country") or data.get("country") or "").strip().upper() or None
            proxy_group = str(data.get("proxy_group") or data.get("group") or "").strip() or None
            proxy_scheme = str(data.get("proxy_scheme") or data.get("scheme") or config.get("proxy_default_scheme") or "http").strip().lower() or "http"
            if mailbox_content.strip() and hasattr(free_manager, "pool"):
                free_manager.pool.import_text(mailbox_content)
            if proxy_content.strip() and hasattr(free_manager, "proxies"):
                importer = free_manager.proxies.import_text
                import_free_proxies(
                    importer,
                    proxy_content,
                    country=proxy_country,
                    group=proxy_group,
                    scheme=proxy_scheme,
                )
            start_kwargs = {
                "pool_content": mailbox_content if free_config_store is None else "",
                "proxy_content": proxy_content if free_config_store is None else "",
            }
            if isinstance(data.get("row_ids"), list) and data.get("row_ids"):
                start_kwargs["row_ids"] = [str(value or "") for value in data.get("row_ids")]
            start_callback = free_manager.start
            accepts_start = signature_accepts_call(start_callback, config, **start_kwargs)
            if accepts_start is False:
                legacy_kwargs = dict(start_kwargs)
                legacy_kwargs.pop("row_ids", None)
                if "row_ids" not in start_kwargs or signature_accepts_call(start_callback, config, **legacy_kwargs) is not True:
                    raise TypeError("Free 启动器签名不兼容")
                start_kwargs = legacy_kwargs
            result = start_callback(config, **start_kwargs)
            return module.jsonify(ok=True, batch_id=result.get("batch_id"), batch={"batch_id": result.get("batch_id"), "members": result.get("tasks") or []}, state=free_state())
        except Exception as exc:
            return free_failure_response(exc, default_code="free_run_start", default_label="启动 Free 注册")
        finally:
            free_request_lock.release()

    def api_free_state():
        try:
            current_state = free_state()
        except Exception as exc:
            return free_state_failure_response(exc)
        try:
            current_config = free_config_public()
        except Exception as exc:
            return free_failure_response(
                exc,
                default_code="free_config_read",
                default_label="读取 Free 配置",
                status=503,
            )
        return module.jsonify(ok=True, state=current_state, config=current_config)

    def api_free_preflight():
        if free_manager is None or free_config_store is None:
            return module.jsonify(ok=False, error="Free 注册服务尚未初始化"), 503
        conflict = free_mutation_conflict("执行 Free 预检")
        if conflict is not None:
            return conflict
        if not free_request_lock.acquire(blocking=False):
            return module.jsonify(ok=False, error="Free 配置、预检或启动请求正在处理中", state=free_state()), 409
        try:
            data = module.request.get_json(silent=True) or {}
            if not isinstance(data, Mapping):
                return free_failure_response(ValueError("配置必须是 JSON 对象"), default_code="free_preflight", default_label="Free 注册预检")
            config = save_free_config(data)
            result = free_manager.preflight(config, proxy_content=str(data.get("proxy_content") or ""))
            return module.jsonify(ok=True, result=result, state=free_state(), config=free_config_public())
        except Exception as exc:
            return free_failure_response(exc, default_code="free_preflight", default_label="Free 注册预检", status=502 if not isinstance(exc, ValueError) else 400)
        finally:
            free_request_lock.release()

    def api_free_start():
        data = module.request.get_json(silent=True) or {}
        return start_free_from_request(data)

    def api_free_stop():
        if free_manager is None:
            return module.jsonify(ok=False, error="Free 注册服务尚未初始化"), 503
        free_manager.stop()
        return module.jsonify(ok=True, state=free_state())

    def api_free_logs():
        task_id = str(module.request.args.get("task_id") or "").strip()
        rows = []
        reader = getattr(free_manager, "public_logs", None) if free_manager is not None else None
        if callable(reader):
            try:
                accepts_task_id = signature_accepts_call(reader, task_id)
                if accepts_task_id is False:
                    if signature_accepts_call(reader) is not True:
                        raise TypeError("Free 日志读取器签名不兼容")
                    rows = reader()
                else:
                    rows = reader(task_id)
            except Exception as exc:
                return free_failure_response(
                    exc,
                    default_code="free_logs_read",
                    default_label="读取 Free 账号日志",
                    status=503,
                )
        return module.jsonify(ok=True, task_id=task_id, logs=rows)

    def _free_error_detail(exc: Exception, code: str = "") -> str:
        # The shared mapper carries the last OAuth task context. Keep an
        # isolated Free node's own diagnostic, especially proxy preflight,
        # from being rewritten as an unrelated OAuth/TLS failure.
        if str(code or getattr(exc, "node_code", "") or "").startswith("free_"):
            return _safe_free_message(exc) or "Free 注册失败"
        return context.safe_runtime_error(exc)

    def free_error_response(exc: Exception, *, default_code: str, default_label: str, status: int = 400):
        return free_failure_response(
            exc,
            default_code=default_code,
            default_label=default_label,
            status=status,
        )

    free_pool_routes = FreePoolRouteController(
        module=module,
        manager=free_manager,
        config_store=free_config_store,
        state=free_state,
        mutation_conflict=free_mutation_conflict,
        error_response=free_error_response,
        failure_response=free_failure_response,
        request_lock=free_request_lock,
        ordinary_mailbox_import=mailbox_admin.import_mailboxes,
    )

    def mailbox_manager():
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
            payload = explicit_failure_payload(
                node_code="email_code_lookup", node_label="查询邮箱验证码",
                error_code="mailbox_latest_code_failed",
                cause=f"邮箱验证码读取异常（{type(exc).__name__}）",
                retryable=True, http_status=500,
            )
            logs.add(f"[{payload['node_label']}/{payload['node_code']}] {payload['error']}", "error")
            return module.jsonify(payload), 500

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
        except Exception as exc:
            payload = explicit_failure_payload(
                node_code="mailbox_password_reveal", node_label="读取邮箱密码",
                error_code="mailbox_password_reveal_failed",
                cause=f"邮箱密码存储读取异常（{type(exc).__name__}）", http_status=500,
            )
            return module.jsonify(payload), 500

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
        except Exception as exc:
            payload = explicit_failure_payload(
                node_code="mailbox_totp_reveal", node_label="读取临时 2FA 验证码",
                error_code="mailbox_totp_reveal_failed",
                cause=f"2FA 密钥存储读取异常（{type(exc).__name__}）", http_status=500,
            )
            return module.jsonify(payload), 500

    api_mailboxes_url = runtime_info_routes.mailbox_url
    api_runtime_task_mailbox_url = runtime_info_routes.runtime_task_mailbox_url
    api_runtime_task_latest_code = runtime_info_routes.runtime_task_latest_code
    api_runtime_task_mailbox_password = runtime_info_routes.runtime_task_mailbox_password
    api_runtime_task_mailbox_totp = runtime_info_routes.runtime_task_mailbox_totp

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
                    error=f"重登邮箱校验失败：服务返回了无效的 {type(selected).__name__} 结果",
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
                batch_id=allocate_run_batch_id(context, batch_started_at, logs),
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
            payload = explicit_failure_payload(
                node_code="relogin_start", node_label="启动重登任务",
                error_code="relogin_start_failed", cause=context.safe_runtime_error(exc),
                state=public_state(), http_status=400,
            )
            return module.jsonify(payload), 400
        except Exception as exc:
            payload = explicit_failure_payload(
                node_code="relogin_start", node_label="启动重登任务",
                error_code="relogin_start_failed",
                cause=f"重登任务启动异常（{type(exc).__name__}）",
                state=public_state(), retryable=True, http_status=500,
                action_hint="刷新邮箱状态并检查本地服务后重试。",
            )
            logs.add(f"[{payload['node_label']}/{payload['node_code']}] {payload['error']}", "error")
            return module.jsonify(payload), 500
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

    def request_json_object() -> dict[str, Any]:
        value = module.request.get_json(silent=True) or {}
        return dict(value) if isinstance(value, Mapping) else {}

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
            payload = explicit_failure_payload(
                node_code="sub2_export",
                node_label="SUB2API 导出",
                error_code="sub2_export_failed",
                cause=public_message or context.safe_runtime_error(exc),
                action_hint="确认所选账号结果包含完整且经过校验的 SUB2 Token。",
            )
            logs.add(f"[SUB2API 导出/sub2_export] {payload['error']}", "error")
            return module.jsonify(payload), 400

    api_run_batches = runtime_info_routes.run_batches
    api_run_batch = runtime_info_routes.run_batch

    sms_balance_routes = SmsBalanceRouteController(
        module=module,
        context=context,
        secrets_for=route_secrets,
    )
    api_sms_balances = sms_balance_routes.query

    local_config_routes = LocalConfigRouteController(
        module=module,
        context=context,
        importer=importer,
        settings=settings,
        public_state=public_state,
        busy_response=busy_response,
    )
    api_local_config = local_config_routes.get
    api_local_config_export = local_config_routes.export
    api_local_config_import = local_config_routes.import_config
    api_local_config_secret = local_config_routes.secret

    def api_notification_email_test():
        try:
            data = module.request.get_json(silent=True) or {}
            if not isinstance(data, dict):
                return module.jsonify(ok=False, error="配置必须是 JSON 对象"), 400
            result = context.test_email_notification(data)
            return module.jsonify(ok=True, notification=result, state=public_state())
        except ValueError as exc:
            payload = explicit_failure_payload(
                node_code="notification_test", node_label="测试邮件通知",
                error_code="notification_test_failed", cause=context.safe_runtime_error(exc),
                secrets=route_secrets(data), state=public_state(), http_status=400,
                action_hint="检查 SMTP 地址、授权码和收件地址。",
            )
            return module.jsonify(payload), 400
        except Exception as exc:
            payload = explicit_failure_payload(
                node_code="notification_test",
                node_label="测试邮件通知",
                error_code="notification_test_failed",
                cause=context.safe_runtime_error(exc),
                secrets=route_secrets(data),
                state=public_state(),
                retryable=True,
                http_status=502,
                action_hint="检查 SMTP 地址、授权码、收件地址和当前网络。",
            )
            logs.add(f"[测试邮件通知/notification_test] {payload['error']}", "error")
            return module.jsonify(payload), 502

    try:
        from .free_account_routes import FreeAccountRouteController
    except ImportError:
        from free_account_routes import FreeAccountRouteController  # type: ignore[no-redef]
    free_account_routes = FreeAccountRouteController(
        module=module,
        manager=free_manager,
        config_store=free_config_store,
        free_state=free_state,
        error_response=free_error_response,
    )

    # Rebind owns an independent mailbox pool and task state.  Construct it
    # beside the Free registration manager, but keep its worker and routes
    # isolated from the registration driver and RoxyBrowser lifecycle.
    try:
        from .free_rebind_runtime import FreeRebindService
        from .free_rebind_routes import FreeRebindRouteController
    except ImportError:
        from free_rebind_runtime import FreeRebindService  # type: ignore[no-redef]
        from free_rebind_routes import FreeRebindRouteController  # type: ignore[no-redef]
    rebind_root = context.free_data_dir
    if rebind_root is None and free_manager is not None:
        rebind_root = getattr(free_manager, "data_dir", None)
    rebind_config_provider = getattr(free_config_store, "load", None) if free_config_store is not None else None
    free_rebind_service = (
        FreeRebindService(
            rebind_root,
            free_manager=free_manager,
            config_provider=rebind_config_provider,
            log_fn=getattr(free_manager, "_log", None),
        )
        if free_manager is not None and rebind_root is not None
        else None
    )
    if free_rebind_service is not None:
        app.extensions["gptphone_free_rebind"] = free_rebind_service
    free_rebind_routes = FreeRebindRouteController(
        module=module,
        service=free_rebind_service,
        error_response=free_error_response,
    )
    diagnostic_routes = None
    if diagnostic_store is not None:
        try:
            from .diagnostic_routes import DiagnosticRouteController
        except ImportError:  # pragma: no cover
            from diagnostic_routes import DiagnosticRouteController  # type: ignore[no-redef]
        diagnostic_routes = DiagnosticRouteController(module=module, store=diagnostic_store)
    parser_sample_routes = MailboxParserSampleRouteController(
        module=module,
        ordinary_store=context.mailbox_parser_sample_store,
        free_store=context.free_mailbox_parser_sample_store,
    )

    routes = (
        ("/mailboxes", "mailbox_manager", mailbox_manager, ["GET"]),
        ("/splitter", "mailbox_splitter", mailbox_manager, ["GET"]),
        ("/url-test", "mailbox_url_test_page", mailbox_manager, ["GET"]),
        ("/mailbox-parser-samples", "mailbox_parser_samples_page", mailbox_manager, ["GET"]),
        # Legacy deep links remain harmless aliases; the account-management menu is gone.
        ("/accounts", "account_manager", mailbox_manager, ["GET"]),
        ("/settings", "settings_page", mailbox_manager, ["GET"]),
        ("/api/mailboxes", "api_mailboxes", api_mailboxes, ["GET"]),
        ("/api/free/config", "api_free_config", free_control_routes.config, ["GET", "POST"]),
        ("/api/free/config/secret", "api_free_config_secret", free_control_routes.config_secret, ["POST"]),
        ("/api/free/state", "api_free_state", api_free_state, ["GET"]),
        ("/api/free/preflight", "api_free_preflight", api_free_preflight, ["POST"]),
        ("/api/free/start", "api_free_start", api_free_start, ["POST"]),
        ("/api/free/stop", "api_free_stop", api_free_stop, ["POST"]),
        ("/api/free/logs", "api_free_logs", api_free_logs, ["GET"]),
        ("/api/diagnostics/search", "api_diagnostics_search", diagnostic_routes.search if diagnostic_routes else lambda: module.jsonify(ok=False, error="日志中心尚未初始化"), ["POST"]),
        ("/api/diagnostics/incidents/<incident_id>", "api_diagnostics_incident", diagnostic_routes.incident if diagnostic_routes else lambda incident_id: module.jsonify(ok=False, error="日志中心尚未初始化"), ["GET"]),
        ("/api/diagnostics/export", "api_diagnostics_export", diagnostic_routes.export if diagnostic_routes else lambda: module.jsonify(ok=False, error="日志中心尚未初始化"), ["POST"]),
        ("/api/diagnostics/delete", "api_diagnostics_delete", diagnostic_routes.delete if diagnostic_routes else lambda: module.jsonify(ok=False, error="日志中心尚未初始化"), ["POST"]),
        ("/api/diagnostics/clear-all", "api_diagnostics_clear_all", diagnostic_routes.clear_all if diagnostic_routes else lambda: module.jsonify(ok=False, error="日志中心尚未初始化"), ["POST"]),
        ("/api/diagnostics/health", "api_diagnostics_health", diagnostic_routes.health if diagnostic_routes else lambda: module.jsonify(ok=False, error="日志中心尚未初始化"), ["GET"]),
        ("/api/free/tasks/delete", "api_free_tasks_delete", free_control_routes.delete_tasks, ["POST"]),
        ("/api/free/roxy/workspaces", "api_free_roxy_workspaces", free_account_routes.roxy_workspaces, ["GET"]),
        *free_pool_routes.routes(),
        ("/api/free/mailboxes/url", "api_free_mailbox_url", free_account_routes.mailbox_url, ["POST"]),
        ("/api/free/mailboxes/latest-code", "api_free_mailbox_latest_code", free_account_routes.mailbox_latest_code, ["POST"]),
        ("/api/free/tasks/latest-code", "api_free_task_latest_code", free_account_routes.task_latest_code, ["POST"]),
        ("/api/free/2fa/retry", "api_free_twofa_retry", free_account_routes.retry_twofa, ["POST"]),
        ("/api/free/retry/batch", "api_free_retry_batch", free_account_routes.batch_retry, ["POST"]),
        ("/api/free/rerun", "api_free_rerun", free_account_routes.rerun, ["POST"]),
        ("/api/free/live-check", "api_free_live_check", free_account_routes.live_check, ["POST"]),
        ("/api/free/live-check/state", "api_free_live_check_state", free_account_routes.live_check_state, ["GET"]),
        ("/api/free/plan-check", "api_free_plan_check", free_account_routes.plan_check, ["POST"]),
        ("/api/free/plan-check/state", "api_free_plan_check_state", free_account_routes.plan_check_state, ["GET"]),
        ("/api/free/rebind/state", "api_free_rebind_state", free_rebind_routes.state, ["GET"]),
        ("/api/free/rebind/mailboxes", "api_free_rebind_mailboxes", free_rebind_routes.mailboxes, ["GET"]),
        ("/api/free/rebind/mailboxes/url", "api_free_rebind_mailboxes_url", free_rebind_routes.mailbox_url, ["POST"]),
        ("/api/free/rebind/mailboxes/import", "api_free_rebind_mailboxes_import", free_rebind_routes.import_mailboxes, ["POST"]),
        ("/api/free/rebind/mailboxes/latest-code", "api_free_rebind_mailboxes_latest_code", free_rebind_routes.mailbox_latest_code, ["POST"]),
        ("/api/free/rebind/mailboxes/delete", "api_free_rebind_mailboxes_delete", free_rebind_routes.delete_mailboxes, ["POST"]),
        ("/api/free/rebind/mailboxes/available", "api_free_rebind_mailboxes_available", lambda: free_rebind_routes.mailbox_status("available"), ["POST"]),
        ("/api/free/rebind/mailboxes/unavailable", "api_free_rebind_mailboxes_unavailable", lambda: free_rebind_routes.mailbox_status("unavailable"), ["POST"]),
        ("/api/free/rebind/start", "api_free_rebind_start", free_rebind_routes.start, ["POST"]),
        ("/api/free/rebind/retry", "api_free_rebind_retry", free_rebind_routes.retry, ["POST"]),
        ("/api/free/rebind/stop", "api_free_rebind_stop", free_rebind_routes.stop, ["POST"]),
        *mailbox_mutation_routes.routes(),
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
        (
            "/api/runtime/tasks/latest-code",
            "api_runtime_task_latest_code",
            api_runtime_task_latest_code,
            ["POST"],
        ),
        (
            "/api/runtime/tasks/mailbox-password",
            "api_runtime_task_mailbox_password",
            api_runtime_task_mailbox_password,
            ["POST"],
        ),
        (
            "/api/runtime/tasks/mailbox-totp",
            "api_runtime_task_mailbox_totp",
            api_runtime_task_mailbox_totp,
            ["POST"],
        ),
        ("/api/mailboxes/relogin", "api_mailboxes_relogin", api_mailboxes_relogin, ["POST"]),
        ("/api/mailbox-url-test", "api_mailbox_url_test", api_mailbox_url_test, ["POST"]),
        ("/api/mailbox-parser-samples/status", "api_mailbox_parser_samples_status", parser_sample_routes.status, ["POST"]),
        ("/api/mailbox-parser-samples/delete", "api_mailbox_parser_samples_delete", parser_sample_routes.delete, ["POST"]),
        ("/api/mailbox-parser-samples/cleanup", "api_mailbox_parser_samples_cleanup", parser_sample_routes.cleanup, ["POST"]),
        ("/api/mailbox-parser-samples/export", "api_mailbox_parser_samples_export", parser_sample_routes.export, ["POST"]),
        ("/api/mailbox-parser-samples/health", "api_mailbox_parser_samples_health", parser_sample_routes.health, ["GET"]),
        ("/api/mailbox-parser-samples", "api_mailbox_parser_samples", parser_sample_routes.list, ["GET"]),
        ("/api/mailbox-parser-samples/<sample_id>", "api_mailbox_parser_sample_detail", parser_sample_routes.detail, ["GET"]),
        ("/api/mailbox-parser-samples/<sample_id>/reveal", "api_mailbox_parser_sample_reveal", parser_sample_routes.reveal, ["POST"]),
        ("/api/mailbox-parser-samples/<sample_id>/reparse", "api_mailbox_parser_sample_reparse", parser_sample_routes.reparse, ["POST"]),
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
        ("/api/mailboxes/sub2-export", "api_mailboxes_sub2_export", api_mailboxes_sub2_export, ["POST"]),
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
