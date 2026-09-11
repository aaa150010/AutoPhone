"""Domain-grouped Flask route view builders extracted from web_routes.

The builders replay the original ``patch_flask_app`` construction order and
share one namespace so cross-group lookups stay late-bound exactly like the
former closure variables.
"""

from __future__ import annotations

try:
    from .numeric_coerce import coerce_int as _coerce_int_impl
except ImportError:  # pragma: no cover - top-level recovery import
    from numeric_coerce import coerce_int as _coerce_int_impl  # type: ignore[no-redef]

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
import socket
import threading
import time
from typing import Any
import uuid

try:
    from .mailbox_batch_operations import MailboxBatchRouteController
    from .run_notifications import NotificationConfigError
except ImportError:  # Loaded as a top-level runtime override by web_gui.py.
    from mailbox_batch_operations import MailboxBatchRouteController  # type: ignore[no-redef]
    from run_notifications import NotificationConfigError  # type: ignore[no-redef]

try:
    from .mailbox_mutation_routes import MailboxMutationRouteController
except ImportError:  # Loaded as a top-level runtime override by web_gui.py.
    from mailbox_mutation_routes import MailboxMutationRouteController  # type: ignore[no-redef]

try:
    from .batch_identity import allocate_run_batch_id
except ImportError:  # Loaded as a top-level runtime override by web_gui.py.
    from batch_identity import allocate_run_batch_id  # type: ignore[no-redef]

try:
    from .local_config_routes import LocalConfigRouteController
    from .runtime_info_routes import RuntimeInfoRouteController
    from .mailbox_parser_sample_routes import MailboxParserSampleRouteController
    from .route_failures import explicit_failure_payload
    from .sms_balance_routes import SmsBalanceRouteController
except ImportError:  # Loaded as a top-level runtime override by web_gui.py.
    from local_config_routes import LocalConfigRouteController  # type: ignore[no-redef]
    from runtime_info_routes import RuntimeInfoRouteController  # type: ignore[no-redef]
    from mailbox_parser_sample_routes import MailboxParserSampleRouteController  # type: ignore[no-redef]
    from route_failures import explicit_failure_payload  # type: ignore[no-redef]
    from sms_balance_routes import SmsBalanceRouteController  # type: ignore[no-redef]

try:
    from .free_register_common import FIXED_PASSWORD as _FREE_FIXED_PASSWORD, safe_log_message as _safe_free_message
    from .free_failure_runtime import canonical_failure as _canonical_free_failure, exception_to_failure as _free_exception_to_failure
    from .diagnostic_writer import DiagnosticEventWriter, LogContext
    from .diagnostic_writer_async import AsyncDiagnosticWriter as _AsyncDiagnosticWriter
    from .free_register_start_async import (
        FreeStartAsyncCoordinator,
        FreeStartInProgressError,
    )
    from .free_register_common import FreeRegisterError as _FreeRegisterRouteError
    from .free_config_routes import FreeControlRouteController
    from .free_pool_routes import (
        FreePoolRouteController,
        import_free_proxies,
        signature_accepts_call,
    )
except ImportError:
    from free_register_common import FIXED_PASSWORD as _FREE_FIXED_PASSWORD, safe_log_message as _safe_free_message  # type: ignore[no-redef]
    from free_failure_runtime import canonical_failure as _canonical_free_failure, exception_to_failure as _free_exception_to_failure  # type: ignore[no-redef]
    from diagnostic_writer import DiagnosticEventWriter, LogContext  # type: ignore[no-redef]
    from diagnostic_writer_async import AsyncDiagnosticWriter as _AsyncDiagnosticWriter  # type: ignore[no-redef]
    from free_register_start_async import (  # type: ignore[no-redef]
        FreeStartAsyncCoordinator,
        FreeStartInProgressError,
    )
    from free_register_common import FreeRegisterError as _FreeRegisterRouteError  # type: ignore[no-redef]
    from free_config_routes import FreeControlRouteController  # type: ignore[no-redef]
    from free_pool_routes import (  # type: ignore[no-redef]
        FreePoolRouteController,
        import_free_proxies,
        signature_accepts_call,
    )

_SHA256_HEX_CHARACTERS = frozenset("0123456789abcdef")



try:
    from .quiet_note import note_stderr
except ImportError:  # pragma: no cover - top-level recovery import
    from quiet_note import note_stderr  # type: ignore[no-redef]

def _note_stderr(where: str, exc: BaseException) -> None:
    note_stderr('web_routes_sections', where, exc)


def _remail_public_text(value: Any, limit: int) -> str | None:
    """Return a bounded plain-text scalar, or None when not forwardable."""
    if value is None or isinstance(value, (dict, list, tuple, set, bool)):
        return None
    text = str(value).strip()
    if not text or len(text) > max(1, int(limit)):
        return None
    return text


def _remail_public_number(value: Any, *, integer: bool = False) -> int | float | None:
    """Return a finite bounded number, or None when not forwardable."""
    if isinstance(value, bool):
        return None
    try:
        parsed = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    if parsed != parsed or parsed in {float("inf"), float("-inf")} or parsed < 0.0:
        return None
    return int(parsed) if integer else parsed


# Whitelist of models written into SUB2API export credentials.  Upstream
# consumers expect an explicit mapping; extend this constant when new ChatGPT
# model slugs must be exported.  Maintenance point for SUB2 model_mapping.
SUB2_EXPORT_MODEL_MAPPING = {
    "gpt-5.4": "gpt-5.4",
    "gpt-5.4-mini": "gpt-5.4-mini",
    "gpt-5.5": "gpt-5.5",
    "gpt-5.6-luna": "gpt-5.6-luna",
    "gpt-5.6-terra": "gpt-5.6-terra",
}


def _safe_int(value: Any, default: int) -> int:
    return _coerce_int_impl(value, default)


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
class RouteScope:
    """Late-bound dependencies shared by the three route builders.

    ``host`` is the ``web_routes`` module itself so route bodies can resolve
    symbols that tests patch on that module at request time.
    """

    host: Any
    module: Any
    context: Any
    app: Any
    importer: Any
    logs: Any
    settings: Any
    state: Any
    store: Any
    mailbox_admin: Any
    free_manager: Any
    free_config_store: Any
    diagnostic_store: Any




def build_core_routes(scope: RouteScope, ns: dict[str, Any]) -> dict[str, Any]:
    """Build the recovered dashboard views: SPA hosting, state, config, and run control."""
    def route_secrets(config: Any) -> Sequence[Any]:
        if scope.context.failure_secrets is None or not isinstance(config, dict):
            return ()
        try:
            return scope.context.failure_secrets(config)
        except Exception:
            return ()
    if scope.context.run_batch_manifest is not None:
        scope.context.run_batch_manifest.log_fn = scope.logs.add
    initial_config = scope.store.load()
    scope.context.write_local_config(
        scope.context.local_config_from_runtime(initial_config, scope.context.read_local_config())
    )
    scope.context.configure_sms_pool(initial_config, logs=scope.logs, importer=scope.importer)

    frontend_dist = scope.context.app_dir / "frontend" / "dist"

    def _vite_dev_server_alive() -> bool:
        try:
            with socket.create_connection(("127.0.0.1", 5173), timeout=0.25):
                return True
        except OSError:
            return False

    def spa_index():
        # While the start.command Vite dev server is running, the browser
        # entry always follows hot-reload: never serve a stale built bundle
        # over it. When Vite is down, fall back to the last build with a
        # no-cache entry so a fresh bundle is picked up after every rebuild.
        if _vite_dev_server_alive():
            request = scope.module.request
            current_url = str(request.url)
            target = current_url.replace(f":{request.port}/", ":5173/", 1)
            if target != current_url:
                return scope.module.redirect(target)
        response = scope.context.send_from_directory(str(frontend_dist), "index.html")
        response.headers["Cache-Control"] = "no-cache"
        return response

    def spa_asset(filename):
        return scope.context.send_from_directory(str(frontend_dist / "assets"), filename)

    if frontend_dist.exists():
        if "index" in scope.app.view_functions:
            scope.app.view_functions["index"] = spa_index
        else:
            scope.app.add_url_rule("/", "index", spa_index, methods=["GET"])
        if "spa_asset" not in scope.app.view_functions:
            scope.app.add_url_rule("/assets/<path:filename>", "spa_asset", spa_asset, methods=["GET"])
        # Vue navigation is history-based.  Register the user-facing deep
        # links explicitly so refreshing a page such as /free-mailboxes does
        # not fall through to Flask's 404 before the SPA can restore state.
        for path in (
            "/free-register",
            "/free-mailboxes",
            "/free-rebind",
            "/remail/purchase",
            "/remail/orders",
            "/network-tools",
            "/logs",
            "/mailbox-parser-samples",
        ):
            endpoint = f"spa_deep_link_{path.strip('/').replace('-', '_')}"
            if endpoint not in scope.app.view_functions:
                scope.app.add_url_rule(path, endpoint, spa_index, methods=["GET"])

    def public_state():
        return scope.context.masked_state(scope.state())

    def busy_response(message="另一个配置、预检或启动请求正在处理中"):
        return scope.module.jsonify(ok=False, error=message, state=public_state()), 409

    def restore_active_config(previous_config, previous_local_config):
        rollback_failed = False
        for action in (
            lambda: scope.store.save(previous_config),
            lambda: scope.context.configure_sms_pool(previous_config, logs=scope.logs, importer=scope.importer),
            lambda: scope.context.write_local_config(previous_local_config),
        ):
            try:
                action()
            except Exception:
                rollback_failed = True
        if rollback_failed:
            scope.logs.add("配置应用失败，上一版本未能完整恢复，请重新保存配置", "error")

    def save_active_config(data):
        previous_config = scope.store.load()
        previous_local_config = scope.context.read_local_config()
        prepared = scope.context.apply_server_defaults(data)
        try:
            saved = scope.store.save(prepared)
            scope.context.configure_sms_pool(saved, logs=scope.logs, importer=scope.importer)
            local_config = scope.context.local_config_from_runtime(saved, previous_local_config)
            scope.context.write_local_config(local_config)
        except Exception:
            restore_active_config(previous_config, previous_local_config)
            raise
        return saved

    def api_state():
        return scope.module.jsonify(ok=True, state=public_state())

    if "api_state" in scope.app.view_functions:
        scope.app.view_functions["api_state"] = api_state

    def save_config():
        if not scope.context.lifecycle_lock.acquire(blocking=False):
            return busy_response()
        data: dict[str, Any] = {}
        try:
            if scope.importer.status(scope.settings()).get("running"):
                return scope.module.jsonify(
                    ok=False,
                    error="任务运行中，停止后才能修改配置",
                    state=public_state(),
                ), 409
            data = scope.module.request.get_json(silent=True) or {}
            if not isinstance(data, dict):
                return scope.module.jsonify(ok=False, error="配置必须是 JSON 对象"), 400

            data.pop("pool_content", None)
            saved = save_active_config(data)
            scope.logs.add("独立导入器配置已保存到本工具 data 目录", "success")
            return scope.module.jsonify(
                ok=True,
                settings=scope.context.masked_local_config(saved),
                state=public_state(),
            )
        except ValueError as exc:
            payload = explicit_failure_payload(
                node_code="config_save", node_label="保存运行配置", error_code="config_validation_failed",
                cause=scope.context.safe_runtime_error(exc),
                secrets=route_secrets(data), state=public_state(), http_status=400,
            )
            return scope.module.jsonify(payload), 400
        except Exception as exc:
            payload = explicit_failure_payload(
                node_code="config_save", node_label="保存运行配置", error_code="config_save_failed",
                cause=scope.context.safe_runtime_error(exc),
                secrets=route_secrets(data), state=public_state(), http_status=500,
                action_hint="检查配置格式和本地数据目录后重试。",
            )
            scope.logs.add(f"[{payload['node_label']}/{payload['node_code']}] {payload['error']}", "error")
            return scope.module.jsonify(payload), 500
        finally:
            scope.context.lifecycle_lock.release()

    if "save_config" in scope.app.view_functions:
        scope.app.view_functions["save_config"] = save_config

    def stop():
        with scope.context.lifecycle_lock:
            scope.importer.stop()
        return scope.module.jsonify(ok=True, state=public_state())

    if "stop" in scope.app.view_functions:
        scope.app.view_functions["stop"] = stop

    def preflight():
        if not scope.context.lifecycle_lock.acquire(blocking=False):
            return busy_response()
        try:
            if scope.importer.status(scope.settings()).get("running"):
                return scope.module.jsonify(
                    ok=False,
                    error="任务运行中，停止后才能执行预检",
                    state=public_state(),
                ), 409
            data = scope.module.request.get_json(silent=True) or {}
            if not isinstance(data, dict):
                return scope.module.jsonify(ok=False, error="配置必须是 JSON 对象"), 400
            try:
                scope.context.sms_alerts.begin_run()
                config = save_active_config(data)
                statuses = scope.context.preflight_sms_pool(config, logs=scope.logs, importer=scope.importer)
                result = scope.importer.settings_validation(config, remote=True)
            except Exception as exc:
                status = 400 if isinstance(exc, ValueError) else 502
                payload = explicit_failure_payload(
                    node_code="sms_preflight", node_label="执行启动预检", error_code="sms_preflight_failed",
                    cause=scope.context.safe_runtime_error(exc),
                    secrets=route_secrets(data), state=public_state(),
                    retryable=status >= 500, http_status=status,
                    action_hint="检查接码平台 Key、代理和邮箱池配置后重试。",
                )
                payload["sms_key_statuses"] = scope.context.sms_key_pool.public_statuses()
                scope.logs.add(f"[{payload['node_label']}/{payload['node_code']}] {payload['error']}", "error")
                return scope.module.jsonify(payload), status
            scope.logs.add(
                f"预检通过: 邮箱池 {result['pool']['entries']} 条，"
                f"SUB2 分组 {result['sub2_group']}#{result['sub2_group_id']}",
                "success",
            )
            return scope.module.jsonify(
                ok=True,
                result=result,
                sms_key_statuses=statuses,
                state=public_state(),
            )
        finally:
            scope.context.lifecycle_lock.release()

    if "preflight" in scope.app.view_functions:
        scope.app.view_functions["preflight"] = preflight

    @scope.app.after_request
    def no_cache_response(response):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        return response

    def start_from_request(*, replace_pool: bool):
        if not scope.context.lifecycle_lock.acquire(blocking=False):
            return busy_response("另一个启动请求正在处理中")
        failure_config: dict[str, Any] = {}
        try:
            if scope.importer.status(scope.settings()).get("running"):
                return scope.module.jsonify(
                    ok=False,
                    error="已有任务运行中，请先停止并等待任务结束",
                    state=public_state(),
                ), 409

            data = scope.module.request.get_json(silent=True) or {}
            if not isinstance(data, dict):
                return scope.module.jsonify(ok=False, error="配置必须是 JSON 对象"), 400
            failure_config = dict(data)

            run_mode = str(data.get("run_mode") or "register").strip().lower()
            if run_mode == "free_register":
                return ns["start_free_from_request"](data, legacy=True)

            data.pop("upload_targets", None)
            data.pop("nv_import", None)

            run_mailbox_rows = _normalize_run_mailbox_rows(data.pop("run_mailbox_rows", None))
            if run_mailbox_rows is None:
                return scope.module.jsonify(
                    ok=False,
                    error="本次运行的邮箱行绑定参数无效",
                ), 400
            if run_mailbox_rows:
                persisted_config = scope.store.load()
                if "target_count" in persisted_config:
                    data["target_count"] = persisted_config["target_count"]
                else:
                    data.pop("target_count", None)

            pool_content = data.pop("pool_content", "")
            auto_content = scope.module._clean(pool_content) if replace_pool else ""

            if auto_content:
                path = scope.store.save_pool_text(auto_content)
                data.update({"email_mode": "auto", "pool_path": str(path)})
            cfg = save_active_config(data)
            pool = scope.importer._pool(cfg)

            if auto_content:
                check = pool.validate()
                if not check.get("ok"):
                    return scope.module.jsonify(
                        ok=False,
                        error="; ".join(check.get("errors") or ["邮箱池为空"]),
                        state=public_state(),
                    ), 400
                cleared = pool.reset_for_pool_replacement()
                scope.logs.add(
                    f"本次启动已覆盖自动邮箱池: {check['entries']} 条，清除旧状态 {cleared} 条",
                    "success",
                )
            else:
                check = pool.validate()
                if not check.get("ok"):
                    return scope.module.jsonify(
                        ok=False,
                        error="; ".join(check.get("errors") or ["邮箱池为空"]),
                        state=public_state(),
                    ), 400

            if not replace_pool:
                scope.logs.add(f"使用现有自动邮箱池启动: {check['entries']} 条", "info")
            scope.context.sms_alerts.begin_run()
            scope.context.sms_cost_ledger.clear()
            scope.context.sms_route_policy.reset()
            scope.context.sms_key_pool.begin_run()
            scope.context.sms_phone_gate.begin_run()
            try:
                sms_statuses = scope.context.preflight_sms_pool(cfg, logs=scope.logs, importer=scope.importer)
            except ValueError as exc:
                payload = explicit_failure_payload(
                    node_code="sms_preflight", node_label="执行启动预检", error_code="sms_preflight_failed",
                    cause=scope.context.safe_runtime_error(exc),
                    secrets=route_secrets(failure_config), state=public_state(), http_status=400,
                    action_hint="检查接码平台 Key、代理和邮箱池配置后重试。",
                )
                return scope.module.jsonify(payload), 400
            run_config = dict(cfg)
            batch_started_at = int(time.time())
            run_config["batch_started_at"] = batch_started_at
            run_config["batch_id"] = allocate_run_batch_id(scope.context, batch_started_at, scope.logs)
            run_config["_gptphone_sms_preflight_statuses"] = [
                dict(row)
                for row in sms_statuses or ()
                if isinstance(row, Mapping)
            ]
            if run_mailbox_rows:
                run_config["target_count"] = len(run_mailbox_rows)
                run_config["_gptphone_run_mailbox_rows"] = run_mailbox_rows
            scope.importer.start(run_config)
            batch = (
                scope.context.run_batch_manifest.get(run_config["batch_id"])
                if scope.context.run_batch_manifest is not None
                else None
            )
            return scope.module.jsonify(
                ok=True,
                batch_id=run_config["batch_id"],
                batch=batch,
                state=public_state(),
            )
        except ValueError as exc:
            payload = explicit_failure_payload(
                node_code="run_start", node_label="启动注册任务",
                error_code="run_start_failed", cause=scope.context.safe_runtime_error(exc),
                secrets=route_secrets(failure_config), state=public_state(), http_status=400,
            )
            return scope.module.jsonify(payload), 400
        except Exception as exc:
            payload = explicit_failure_payload(
                node_code="run_start", node_label="启动注册任务",
                error_code="run_start_failed",
                cause=scope.context.safe_runtime_error(exc), secrets=route_secrets(failure_config),
                state=public_state(), retryable=True, http_status=500,
                action_hint="检查运行配置和本地服务状态后重试。",
            )
            scope.logs.add(f"[{payload['node_label']}/{payload['node_code']}] {payload['error']}", "error")
            return scope.module.jsonify(payload), 500
        finally:
            scope.context.lifecycle_lock.release()

    def start():
        return start_from_request(replace_pool=True)

    scope.app.view_functions["start"] = start

    def start_existing():
        return start_from_request(replace_pool=False)

    if "start_existing" not in scope.app.view_functions:
        scope.app.add_url_rule("/api/start-existing", "start_existing", start_existing, methods=["POST"])
    return {
        "route_secrets": route_secrets,
        "spa_index": spa_index,
        "public_state": public_state,
        "busy_response": busy_response,
        "frontend_dist": frontend_dist,
    }



def build_free_routes(scope: RouteScope, ns: dict[str, Any]) -> dict[str, Any]:
    """Build the Free registration control, pool, and status views."""
    free_request_lock = threading.Lock()
    # Async startup coordinator: one background slot owns the heavy section of
    # ``/api/free/start`` so the HTTP click returns immediately.
    _start_coordinator: FreeStartAsyncCoordinator | None = None
    def free_start_coordinator() -> FreeStartAsyncCoordinator:
        nonlocal _start_coordinator
        if _start_coordinator is None:
            _start_coordinator = FreeStartAsyncCoordinator(scope.free_manager)
        return _start_coordinator
    # Route-level failures use the same structured writer as workers.  Keep a
    # bound instance in the closure so this path cannot accidentally bypass
    # field allowlists by calling ``DiagnosticStore.record`` directly.
    free_route_diagnostic_writer = None
    if scope.diagnostic_store is not None:
        try:
            free_route_diagnostic_writer = DiagnosticEventWriter(
                scope.diagnostic_store,
                context=LogContext(chain="free", workflow="route", driver="free"),
            )
        except Exception:
            free_route_diagnostic_writer = None

    def publish_start_failure_event(failure: Mapping[str, Any]) -> None:
        """Surface an async startup failure as a structured diagnostic event."""
        writer = free_route_diagnostic_writer
        if writer is None:
            return
        try:
            writer.record({
                "level": "error",
                "outcome": "error",
                "chain": "free",
                "workflow": "route",
                "driver": "free",
                "node_code": failure.get("node_code") or "free_run_start",
                "node_label": failure.get("node_label") or "启动 Free 注册",
                "message": failure.get("public_message") or "启动 Free 注册失败",
                "failure": failure,
            })
        except Exception as exc:
            # Diagnostic publication must not mask the original start failure.
            _note_stderr("L564", exc)

    def free_state():
        return scope.free_manager.public_state() if scope.free_manager is not None else {"running": False, "tasks": [], "summary": {}}

    def free_config_public():
        return scope.free_config_store.public() if scope.free_config_store is not None else {}

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
        return scope.module.jsonify(payload), 503

    def free_mutation_conflict(action: str):
        """Return a consistent conflict response while Free work owns its pools."""
        try:
            current_state = free_state()
        except Exception as exc:
            return free_state_failure_response(exc)
        running = bool(current_state.get("running"))
        if running:
            return scope.module.jsonify(ok=False, error=f"Free 注册运行中，暂不能{action}，请停止当前批次后重试", state=current_state), 409
        return None

    def free_failure_response(exc: Exception, *, default_code: str, default_label: str, status: int = 400, include_state: bool = True):
        # ``state`` is built under the Free manager lock.  Payload builders
        # that never surface it (Remail upstream routes) must skip the lock
        # entirely, or a busy manager freezes the error response as well.
        current_state: dict[str, Any] | None = None
        if include_state:
            try:
                current_state = free_state()
            except Exception as state_exc:
                return free_state_failure_response(state_exc)
        code = str(getattr(exc, "node_code", "") or default_code)
        label = str(getattr(exc, "node_label", "") or default_label)
        cause = _free_error_detail(exc, code)
        failure = _free_exception_to_failure(
            exc,
            node_code=code,
            node_label=label,
            detail=cause,
        )
        # The canonical failure carries the HTTP status exposed by this route.
        # An explicitly reported upstream/provider status takes precedence;
        # otherwise retain the local API status (for example, read failures
        # are consistently represented as 503).
        provider_status = getattr(exc, "provider_status", None)
        failure["http_status"] = provider_status if provider_status is not None else status
        # ``exception_to_failure`` keeps generic runtime exceptions retryable
        # for worker recovery.  Route validation errors have no explicit
        # retry policy, however, so their HTTP status must determine the
        # public retryable flag instead of inheriting that worker default.
        if not hasattr(exc, "retryable"):
            failure["retryable"] = status >= 500
        failure = _canonical_free_failure(
            failure,
            default_node_code=code,
            default_node_label=label,
            default_retryable=status >= 500,
        ) or failure
        payload: dict[str, Any] = {
            "ok": False,
            "code": failure.get("error_code") or code,
            "node_code": failure.get("node_code") or code,
            "node_label": failure.get("node_label") or label,
            "error_code": failure.get("error_code") or code,
            "error": failure.get("public_message") or cause,
            "failure": failure,
        }
        if current_state is not None:
            payload["state"] = current_state
        if provider_status is not None:
            payload["provider_status"] = provider_status
        incident_id = ""
        if scope.diagnostic_store is not None:
            try:
                writer = free_route_diagnostic_writer
                if writer is None:
                    writer = DiagnosticEventWriter(
                        scope.diagnostic_store,
                        context=LogContext(chain="free", workflow="route", driver="free"),
                    )
                incident_id = writer.record({
                    "level": "error",
                    "outcome": "error",
                    "chain": "free",
                    "workflow": "route",
                    "driver": "free",
                    "node_code": failure.get("node_code") or code,
                    "node_label": failure.get("node_label") or label,
                    "message": failure.get("public_message") or cause,
                    "failure": failure,
                })
            except Exception:
                incident_id = ""
        if incident_id:
            payload["incident_id"] = incident_id
        try:
            if scope.free_manager is not None and callable(getattr(scope.free_manager, "_log", None)):
                # The explicit write above owns this taskless incident. Keep
                # the Free activity log visible without creating a second
                # unrelated diagnostic for the same route exception.
                scope.free_manager._log(
                    f"[{label}/{code}] {payload['error']}"
                    + (f" incident_id={incident_id}" if incident_id else ""),
                    "warn" if incident_id else "error",
                )
        except Exception as exc:
            # Telemetry must not mask the Free route failure surfaced above.
            _note_stderr("L675", exc)
        return scope.module.jsonify(payload), status

    free_control_routes = FreeControlRouteController(
        module=scope.module, manager=scope.free_manager, config_store=scope.free_config_store,
        state=free_state, config_public=free_config_public,
        failure_response=free_failure_response, request_lock=free_request_lock,
    )

    def save_free_config(data: Mapping[str, Any]) -> dict[str, Any]:
        if scope.free_config_store is None:
            value = dict(data)
            value.setdefault("driver", "protocol")
            value.setdefault("concurrency", 3)
            value.setdefault("target_count", 0)
            value.setdefault("proxy_probe_url", "https://chatgpt.com/")
            value.setdefault("account_password", _FREE_FIXED_PASSWORD)
            value.setdefault("auto_set_password", False)
            value.setdefault("auto_set_2fa", True)
            return value
        return scope.free_config_store.save(data)

    def start_free_from_request(raw: Mapping[str, Any], *, legacy: bool = False):
        if scope.free_manager is None:
            return scope.module.jsonify(ok=False, error="Free 注册服务尚未初始化"), 503
        if not free_request_lock.acquire(blocking=False):
            return scope.module.jsonify(ok=False, error="Free 配置、预检或启动请求正在处理中", state=free_state()), 409
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
            config = dict(config_input) if scope.free_config_store is None else save_free_config(config_input)
            if scope.free_config_store is None:
                # Test/legacy route contexts predating the isolated store only
                # have the old stub store; production never takes this branch.
                try:
                    scope.store.save(dict(data))
                except Exception as exc:
                    # A legacy plain-pool save failure must not block the Free config save.
                    _note_stderr("L724", exc)
            mailbox_content = str(data.get("pool_content") or data.get("free_pool_content") or "")
            proxy_content = str(data.get("proxy_content") or data.get("free_proxy_pool_content") or "")
            proxy_country = str(data.get("proxy_country") or data.get("country") or "").strip().upper() or None
            proxy_group = str(data.get("proxy_group") or data.get("group") or "").strip() or None
            proxy_scheme = str(data.get("proxy_scheme") or data.get("scheme") or config.get("proxy_default_scheme") or "socks5").strip().lower() or "socks5"
            if mailbox_content.strip() and hasattr(scope.free_manager, "pool"):
                scope.free_manager.pool.import_text(mailbox_content)
            if proxy_content.strip() and hasattr(scope.free_manager, "proxies"):
                importer = scope.free_manager.proxies.import_text
                import_free_proxies(
                    importer,
                    proxy_content,
                    country=proxy_country,
                    group=proxy_group,
                    scheme=proxy_scheme,
                )
            start_kwargs = {
                "pool_content": mailbox_content if scope.free_config_store is None else "",
                "proxy_content": proxy_content if scope.free_config_store is None else "",
            }
            row_ids: list[str] = []
            if isinstance(data.get("row_ids"), list) and data.get("row_ids"):
                row_ids = [str(value or "") for value in data.get("row_ids")]
                start_kwargs["row_ids"] = row_ids
            start_callback = scope.free_manager.start
            accepts_start = signature_accepts_call(start_callback, config, **start_kwargs)
            if accepts_start is False:
                legacy_kwargs = dict(start_kwargs)
                legacy_kwargs.pop("row_ids", None)
                if "row_ids" not in start_kwargs or signature_accepts_call(start_callback, config, **legacy_kwargs) is not True:
                    raise TypeError("Free 启动器签名不兼容")
                start_kwargs = legacy_kwargs
            # The heavy section (protocol preflight, full-pool account evidence
            # scan, proxy binding, executor creation) runs on the async
            # coordinator so the click returns in about a second. Startup
            # failures surface as structured diagnostic events and in the
            # state payload instead of blocking this request.
            coordinator = free_start_coordinator()
            try:
                result = coordinator.start_in_background(
                    config,
                    pool_content=start_kwargs["pool_content"],
                    proxy_content=start_kwargs["proxy_content"],
                    row_ids=row_ids,
                    on_error=publish_start_failure_event,
                )
            except FreeStartInProgressError:
                busy = _FreeRegisterRouteError(
                    "free_run_start", "启动 Free 注册", "上一次启动仍在准备中，请稍候", retryable=False,
                    error_code="free_start_in_progress",
                )
                return free_failure_response(busy, default_code="free_run_start", default_label="启动 Free 注册")
            # The coordinator payload already carries a lock-free ``starting``
            # state; calling ``free_state()`` here would take the manager lock
            # and block the response on the background preparation.
            return scope.module.jsonify(ok=True, async_start=True, batch_id=result.get("batch_id"), batch={"batch_id": result.get("batch_id"), "members": result.get("tasks") or []}, state=result.get("state") or free_state())
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
        return scope.module.jsonify(ok=True, state=current_state, config=current_config)

    def api_free_camoufox_debug_state():
        if scope.free_manager is None:
            return scope.module.jsonify(ok=False, error="Free 注册服务尚未初始化"), 503
        try:
            getter = getattr(scope.free_manager, "camoufox_debug_state", None)
            debug = getter() if callable(getter) else {}
            return scope.module.jsonify(ok=True, camoufox_debug=debug, state=free_state())
        except Exception as exc:
            return free_failure_response(
                exc,
                default_code="free_camoufox_debug_state",
                default_label="读取 Camoufox 调试状态",
                status=503,
            )

    def api_free_camoufox_debug_close():
        if scope.free_manager is None:
            return scope.module.jsonify(ok=False, error="Free 注册服务尚未初始化"), 503
        try:
            data = scope.module.request.get_json(silent=True) or {}
            if not isinstance(data, Mapping):
                data = {}
            close = getattr(scope.free_manager, "close_camoufox_debug", None)
            if not callable(close):
                raise RuntimeError("Camoufox 调试关闭接口不可用")
            result = close(str(data.get("session_id") or ""))
            # The manager includes a freshly-read state for direct callers.
            # Pop it before merging the route-level snapshot so a duplicate
            # ``state`` keyword cannot turn a successful close into a 500.
            payload = dict(result) if isinstance(result, Mapping) else {}
            payload.pop("state", None)
            return scope.module.jsonify(ok=True, **payload, state=free_state())
        except Exception as exc:
            return free_failure_response(
                exc,
                default_code="free_camoufox_debug_close",
                default_label="关闭 Camoufox 调试窗口",
                status=400,
            )

    def api_free_preflight():
        if scope.free_manager is None or scope.free_config_store is None:
            return scope.module.jsonify(ok=False, error="Free 注册服务尚未初始化"), 503
        conflict = free_mutation_conflict("执行 Free 预检")
        if conflict is not None:
            return conflict
        if not free_request_lock.acquire(blocking=False):
            return scope.module.jsonify(ok=False, error="Free 配置、预检或启动请求正在处理中", state=free_state()), 409
        try:
            data = scope.module.request.get_json(silent=True) or {}
            if not isinstance(data, Mapping):
                return free_failure_response(ValueError("配置必须是 JSON 对象"), default_code="free_preflight", default_label="Free 注册预检")
            config = save_free_config(data)
            result = scope.free_manager.preflight(config, proxy_content=str(data.get("proxy_content") or ""))
            return scope.module.jsonify(ok=True, result=result, state=free_state(), config=free_config_public())
        except Exception as exc:
            return free_failure_response(exc, default_code="free_preflight", default_label="Free 注册预检", status=502 if not isinstance(exc, ValueError) else 400)
        finally:
            free_request_lock.release()

    def api_free_start():
        data = scope.module.request.get_json(silent=True) or {}
        return start_free_from_request(data)

    def api_free_stop():
        if scope.free_manager is None:
            return scope.module.jsonify(ok=False, error="Free 注册服务尚未初始化"), 503
        scope.free_manager.stop()
        return scope.module.jsonify(ok=True, state=free_state())

    def api_free_logs():
        task_id = str(scope.module.request.args.get("task_id") or "").strip()
        rows = []
        reader = getattr(scope.free_manager, "public_logs", None) if scope.free_manager is not None else None
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
        return scope.module.jsonify(ok=True, task_id=task_id, logs=rows)

    def _free_error_detail(exc: Exception, code: str = "") -> str:
        # The shared mapper carries the last OAuth task context. Keep an
        # isolated Free node's own diagnostic, especially proxy preflight,
        # from being rewritten as an unrelated OAuth/TLS failure.
        if str(code or getattr(exc, "node_code", "") or "").startswith("free_"):
            return _safe_free_message(exc) or "Free 注册失败"
        return scope.context.safe_runtime_error(exc)

    def free_error_response(exc: Exception, *, default_code: str, default_label: str, status: int = 400, include_state: bool = True):
        return free_failure_response(
            exc,
            default_code=default_code,
            default_label=default_label,
            status=status,
            include_state=include_state,
        )

    free_pool_routes = FreePoolRouteController(
        module=scope.module,
        manager=scope.free_manager,
        config_store=scope.free_config_store,
        state=free_state,
        mutation_conflict=free_mutation_conflict,
        error_response=free_error_response,
        failure_response=free_failure_response,
        request_lock=free_request_lock,
        ordinary_mailbox_import=scope.mailbox_admin.import_mailboxes,
    )
    return {
        "start_free_from_request": start_free_from_request,
        "free_state": free_state,
        "free_error_response": free_error_response,
        "api_free_state": api_free_state,
        "api_free_camoufox_debug_state": api_free_camoufox_debug_state,
        "api_free_camoufox_debug_close": api_free_camoufox_debug_close,
        "api_free_preflight": api_free_preflight,
        "api_free_start": api_free_start,
        "api_free_stop": api_free_stop,
        "api_free_logs": api_free_logs,
        "free_control_routes": free_control_routes,
        "free_pool_routes": free_pool_routes,
    }



def build_remail_routes(scope: RouteScope, ns: dict[str, Any]) -> dict[str, Any]:
    """Build the mailbox management, Remail, diagnostics, and local-config views."""
    # Remail Open API upstream responses are forwarded only through explicit
    # field whitelists below.  Unknown keys (and any key/token/credential
    # field) must never reach the browser: the profile endpoint only exposes
    # order/plan metadata and the wallet endpoint only balance fields, each
    # value additionally passed through the public sanitizers.
    _REMAIL_PROFILE_FIELDS: dict[str, Callable[[Any], Any]] = {
        "name": lambda value: _remail_public_text(value, 80),
        "email": lambda value: _remail_public_text(value, 160),
        "plan": lambda value: _remail_public_text(value, 40),
        "status": lambda value: _remail_public_text(value, 40),
        "order_no": lambda value: _remail_public_text(value, 64),
        "orderNo": lambda value: _remail_public_text(value, 64),
        "order_count": lambda value: _remail_public_number(value, integer=True),
        "quota": lambda value: _remail_public_number(value, integer=True),
        "created_at": lambda value: _remail_public_number(value),
        "created_at_text": lambda value: _remail_public_text(value, 40),
    }
    _REMAIL_WALLET_FIELDS: dict[str, Callable[[Any], Any]] = {
        "consumerBalance": lambda value: _remail_public_number(value),
        "balance": lambda value: _remail_public_number(value),
        "amount": lambda value: _remail_public_number(value),
        "currency": lambda value: _remail_public_text(value, 16),
    }
    def _remail_whitelisted(payload: Any, fields: dict[str, Callable[[Any], Any]]) -> dict[str, Any]:
        if not isinstance(payload, Mapping):
            return {}
        result: dict[str, Any] = {}
        for key, clean in fields.items():
            value = clean(payload.get(key))
            if value is not None:
                result[key] = value
        return result

    def _remail_client():
        try:
            from .remail_api import RemailClient
        except ImportError:
            from remail_api import RemailClient  # type: ignore[no-redef]
        cfg = scope.free_config_store.load() if scope.free_config_store is not None else {}
        rcfg = cfg.get("remail") if isinstance(cfg.get("remail"), Mapping) else {}
        key = scope.free_config_store.secret("remail_api_key") if scope.free_config_store is not None else str(rcfg.get("api_key") or "")
        return RemailClient(str(rcfg.get("base_url") or "https://remail.aishop6.com"), key, float(rcfg.get("request_timeout_seconds") or 20))

    def _remail_order_value(value):
        try:
            from .remail_api import remail_order_value
        except ImportError:
            from remail_api import remail_order_value  # type: ignore[no-redef]
        return remail_order_value(value)

    def api_remail_profile():
        try:
            profile = _remail_whitelisted(_remail_client().profile(), _REMAIL_PROFILE_FIELDS)
            return scope.module.jsonify(ok=True, profile=profile)
        except Exception as exc:
            return ns["free_error_response"](exc, default_code="free_remail_profile", default_label="读取 Remail API Key", include_state=False)

    def api_remail_config():
        if scope.free_config_store is None:
            return scope.module.jsonify(ok=False, error="Free 配置尚未初始化"), 503
        if scope.module.request.method == "GET":
            return scope.module.jsonify(ok=True, config=(scope.free_config_store.public().get("remail") or {}), state=scope.free_manager.public_state() if scope.free_manager is not None else {})
        data = scope.module.request.get_json(silent=True) or {}
        if not isinstance(data, Mapping):
            return scope.module.jsonify(ok=False, error="Remail 配置必须是 JSON 对象"), 400
        if scope.free_manager is not None and scope.free_manager.public_state().get("running"):
            return scope.module.jsonify(ok=False, error="Free 任务运行中，停止后才能修改 Remail 配置"), 409
        try:
            current = scope.free_config_store.load()
            merged = dict(current)
            merged["remail"] = dict(data)
            normalized = scope.free_config_store.normalize(merged, previous=current)
            scope.free_config_store.save(normalized)
            return scope.module.jsonify(ok=True, config=(scope.free_config_store.public().get("remail") or {}), state=scope.free_manager.public_state() if scope.free_manager is not None else {})
        except Exception as exc:
            return ns["free_error_response"](exc, default_code="free_remail_config", default_label="保存 Remail 配置")

    def api_remail_key():
        """Reveal the stored Remail API key for local copy, on explicit confirm."""
        import ipaddress as _ipaddress

        request = scope.module.request
        host = str(getattr(request, "remote_addr", "") or "").strip().lower()
        is_loopback = host == "localhost"
        if not is_loopback and host:
            try:
                is_loopback = _ipaddress.ip_address(host).is_loopback
            except ValueError:
                is_loopback = False
        if not is_loopback:
            return scope.module.jsonify(ok=False, error="Remail API Key 仅允许本机查看", code="free_remail_key_loopback_only"), 403
        confirmation = request.get_json(silent=True) or {}
        if not isinstance(confirmation, Mapping) or confirmation.get("confirm_raw") is not True:
            return scope.module.jsonify(ok=False, error="查看 Remail API Key 需要显式确认", code="free_remail_key_confirmation_required"), 400
        if scope.free_config_store is None:
            return scope.module.jsonify(ok=False, error="Free 配置尚未初始化"), 503
        key = scope.free_config_store.secret("remail_api_key")
        return scope.module.jsonify(ok=True, api_key=key, has_key=bool(key.strip()))

    def api_remail_projects():
        try:
            data = _remail_client().projects(status="listed", search="chatgpt")
            return scope.module.jsonify(ok=True, projects=data)
        except Exception as exc:
            return ns["free_error_response"](exc, default_code="free_remail_projects", default_label="读取 Remail 项目", include_state=False)

    def api_remail_wallet():
        try:
            wallet = _remail_whitelisted(_remail_client().wallet(), _REMAIL_WALLET_FIELDS)
            return scope.module.jsonify(ok=True, wallet=wallet)
        except Exception as exc:
            return ns["free_error_response"](exc, default_code="free_remail_wallet", default_label="读取 Remail 钱包", include_state=False)

    def _auto_import_remail_orders(pool, orders: list[Mapping[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Import freshly purchased orders into the Free pool right away.

        A purchase response that already carries the delivery email and
        service token skips the manual order-page import entirely; orders
        still missing their token keep the manual path (import fetches the
        detail lazily).  Individual failures never fail the purchase itself.
        """
        imported: list[dict[str, Any]] = []
        skipped: list[dict[str, Any]] = []
        for order in orders:
            order_no = str(order.get("orderNo") or order.get("order_no") or "").strip()
            try:
                row = pool.import_remail_order(order)
                imported.append({"order_no": order_no, "row_id": row.get("row_id")})
            except Exception as exc:
                skipped.append({"order_no": order_no, "reason": _safe_free_message(exc) or "订单凭证不可用"})
        return imported, skipped

    def _record_remail_purchase_success(*, quantity: int, supply: str, imported: list[dict[str, Any]], skipped: list[dict[str, Any]], duration_ms: int) -> None:
        """Persist one success diagnostic for the purchase route.

        The route used to stay silent on success, so a frozen response left
        no trace in the log center.  The store drops taskless info events, so
        each purchase gets a synthetic per-call execution id; counts stay
        aggregated with no order numbers, emails, or tokens recorded here.
        """
        store = scope.diagnostic_store
        if store is None:
            return
        try:
            writer = DiagnosticEventWriter(store, context=LogContext(chain="free", workflow="route", driver="free"))
            writer.record({
                "level": "info",
                "outcome": "success",
                "chain": "free",
                "workflow": "route",
                "driver": "free",
                "task_id": f"remail-purchase-{uuid.uuid4().hex[:12]}",
                "node_code": "free_remail_purchase",
                "node_label": "购买 Remail 邮箱",
                "message": f"Remail 购买订单已创建：数量 {quantity}，导入 {len(imported)}，待凭证 {len(skipped)}，库存策略 {supply}",
                "duration_ms": int(duration_ms),
            })
        except Exception as exc:
            # Telemetry must not change the purchase response.
            _note_stderr("L1113", exc)

    def api_remail_purchase():
        started = time.monotonic()
        data = scope.module.request.get_json(silent=True) or {}
        if not isinstance(data, Mapping):
            return scope.module.jsonify(ok=False, error="购买参数必须是 JSON 对象"), 400
        try:
            project_id = int(data.get("project_id"))
            suffix = str(data.get("email_suffix") or "").strip()
            quantity = max(1, min(100, int(data.get("quantity") or 1)))
            supply = str(data.get("supply") or "private_first").strip().lower()
            if supply not in {"private_first", "public_only"} or not suffix:
                raise ValueError("购买参数无效")
            client = _remail_client()
            result = client.create_order_batch(project_id, suffix, quantity, supply=supply) if quantity >= 2 else client.create_order(project_id, suffix, supply=supply)
            manager = scope.free_manager
            storage = getattr(getattr(manager, "pool", None), "storage", None) if manager is not None else None
            items = result if isinstance(result, list) else [result]
            normalized_orders: list[Mapping[str, Any]] = []
            for item in items:
                order = _remail_order_value(item)
                if isinstance(order, Mapping):
                    normalized_orders.append(order)
                    if storage is not None:
                        storage.upsert_remail_order(order)
            # Purchased orders flow straight into the Free mailbox pool; the
            # response keeps skip reasons so orders still waiting on Remail
            # side credentials stay visible on the manual order page.
            imported, skipped = _auto_import_remail_orders(manager.pool, normalized_orders) if manager is not None else ([], [])
            # The response must not read manager state: public_state() runs
            # under the manager lock, so a busy batch would freeze the purchase
            # response after the upstream order was already created and paid.
            _record_remail_purchase_success(
                quantity=quantity,
                supply=supply,
                imported=imported,
                skipped=skipped,
                duration_ms=int((time.monotonic() - started) * 1000),
            )
            return scope.module.jsonify(ok=True, result=result, imported=imported, skipped=skipped)
        except Exception as exc:
            return ns["free_error_response"](exc, default_code="free_remail_purchase", default_label="购买 Remail 邮箱", include_state=False)

    def api_remail_orders():
        if scope.free_manager is None:
            return scope.module.jsonify(ok=False, error="Free 注册服务尚未初始化"), 503
        try:
            client = _remail_client()
            args = scope.module.request.args
            page = max(1, int(args.get("page", 1) or 1))
            page_size = max(1, min(100, int(args.get("page_size", 50) or 50)))
            imported_arg = str(args.get("imported", "false") or "false").strip().lower()
            imported_filter = None if imported_arg in {"", "all", "null"} else imported_arg in {"1", "true", "yes", "on"}
            # Failed orders are wrong-parameter residue by default; the order
            # page hides them (and everything already locally dismissed)
            # unless the caller explicitly asks for failed rows.
            include_failed = str(args.get("include_failed", "false") or "false").strip().lower() in {"1", "true", "yes", "on"}
            search = str(args.get("search", "") or "").strip()
            storage = getattr(getattr(scope.free_manager, "pool", None), "storage", None)
            # The Open API is cursor-based.  Pull only enough pages to fill
            # the requested local page, using a 100-item remote page and no
            # per-order detail calls.  Details are fetched lazily during
            # import, where a service token is actually required.
            target_count = page * page_size
            after_id = None
            remote_total = None
            remote_count = 0
            seen_cursors = set()
            for _ in range(100):
                remote = client.orders(afterId=after_id, limit=100, search=search or None)
                items = remote.get("items", []) if isinstance(remote, Mapping) else remote if isinstance(remote, list) else []
                if not isinstance(items, list):
                    items = []
                remote_count += len(items)
                if isinstance(remote, Mapping):
                    remote_total = remote.get("total")
                if storage is not None:
                    # One write transaction per remote page instead of one
                    # per order: 100 individual BEGIN IMMEDIATE commits
                    # serialized the sync behind dozens of fsyncs.
                    page_orders = [order for item in items if (order := _remail_order_value(item)) is not None]
                    if page_orders:
                        storage.upsert_remail_orders(page_orders)
                if storage is None or storage.count_remail_orders(imported=imported_filter, search=search) >= target_count:
                    break
                if not isinstance(remote, Mapping) or not remote.get("hasNext"):
                    break
                next_after = remote.get("nextAfterId")
                if next_after in (None, "", after_id) or next_after in seen_cursors:
                    break
                seen_cursors.add(next_after)
                after_id = next_after
            total = storage.count_remail_orders(imported=imported_filter, search=search, include_hidden=True) if storage is not None else 0
            rows = storage.list_remail_orders(
                imported=imported_filter,
                search=search,
                include_hidden=include_failed,
                public=True,
                limit=page_size,
                offset=(page - 1) * page_size,
            ) if storage is not None else []
            if not include_failed and storage is not None:
                rows = [row for row in rows if str(row.get("status") or "").lower() != "failed"]
            if isinstance(remote_total, int) and imported_filter is None and not search:
                total = remote_total
            return scope.module.jsonify(ok=True, orders=rows, remote_count=remote_count, total=total, page=page, page_size=page_size, has_more=(page * page_size < total))
        except Exception as exc:
            return ns["free_error_response"](exc, default_code="free_remail_orders", default_label="同步 Remail 订单", include_state=False)

    def api_remail_hide_orders():
        """Dismiss wrong-parameter orders locally; re-sync never resurfaces them."""
        if scope.free_manager is None:
            return scope.module.jsonify(ok=False, error="Free 注册服务尚未初始化"), 503
        data = scope.module.request.get_json(silent=True) or {}
        order_nos = [str(value or "").strip() for value in data.get("order_nos", [])] if isinstance(data, Mapping) and isinstance(data.get("order_nos"), list) else []
        storage = getattr(getattr(scope.free_manager, "pool", None), "storage", None)
        if storage is None:
            return scope.module.jsonify(ok=False, error="Free 存储尚未初始化"), 503
        try:
            hidden = storage.hide_remail_orders(order_nos)
            return scope.module.jsonify(ok=True, hidden=hidden)
        except Exception as exc:
            return ns["free_error_response"](exc, default_code="free_remail_hide", default_label="删除 Remail 订单记录", include_state=False)

    def api_remail_import_orders():
        if scope.free_manager is None:
            return scope.module.jsonify(ok=False, error="Free 注册服务尚未初始化"), 503
        data = scope.module.request.get_json(silent=True) or {}
        order_nos = [str(value or "").strip() for value in data.get("order_nos", [])] if isinstance(data, Mapping) and isinstance(data.get("order_nos"), list) else []
        storage = getattr(getattr(scope.free_manager, "pool", None), "storage", None)
        pool = getattr(scope.free_manager, "pool", None)
        imported, skipped = [], []
        if storage is None or pool is None:
            return scope.module.jsonify(ok=False, error="Free 存储尚未初始化"), 503
        try:
            client = _remail_client()
            for order in storage.list_remail_orders(public=False):
                if order_nos and order.get("order_no") not in order_nos:
                    continue
                if order.get("imported"):
                    skipped.append({"order_no": order.get("order_no"), "reason": "已导入"})
                    continue
                if str(order.get("status") or "").lower() not in {"paid", "active", "completed"}:
                    skipped.append({"order_no": order.get("order_no"), "reason": "订单尚未激活"})
                    continue
                try:
                    payload = order.get("payload") if isinstance(order.get("payload"), Mapping) else {}
                    has_token = any(str(payload.get(key) or "").strip() for key in ("serviceToken", "service_token"))
                    if not has_token:
                        detail = _remail_order_value(client.order(str(order.get("order_no") or "")))
                        if detail is not None:
                            storage.upsert_remail_order(detail)
                            order = dict(order)
                            order.update(detail)
                    row = pool.import_remail_order(order)
                    imported.append({"order_no": order.get("order_no"), "row_id": row.get("row_id")})
                except Exception as exc:
                    skipped.append({"order_no": order.get("order_no"), "reason": _safe_free_message(exc) or "订单凭证不可用"})
            return scope.module.jsonify(ok=True, imported=imported, skipped=skipped, rows=pool.public_rows())
        except Exception as exc:
            return ns["free_error_response"](exc, default_code="free_remail_import", default_label="导入 Remail 订单", include_state=False)

    def mailbox_manager():
        if ns["frontend_dist"].exists():
            return ns["spa_index"]()
        return scope.module.Response(scope.context.mailbox_manager_html, mimetype="text/html")

    runtime_info_routes = RuntimeInfoRouteController(
        module=scope.module,
        context=scope.context,
        mailbox_admin=scope.mailbox_admin,
        importer=scope.importer,
        logs=scope.logs,
    )
    api_mailbox_url_test = runtime_info_routes.mailbox_url_test

    mailbox_batch_routes = MailboxBatchRouteController(
        module=scope.module,
        mailbox_admin=scope.mailbox_admin,
        public_state=ns["public_state"],
        logs=scope.logs,
    )
    scope.app.extensions["gptphone_mailbox_batch_operations"] = mailbox_batch_routes.manager
    api_mailboxes = mailbox_batch_routes.mailboxes
    mailbox_mutation_routes = MailboxMutationRouteController(
        module=scope.module,
        mailbox_admin=scope.mailbox_admin,
        public_state=ns["public_state"],
        logs=scope.logs,
        safe_error=scope.context.safe_runtime_error,
        unavailable_action=lambda admin, payload: scope.host.mark_mailboxes_unavailable(
            admin,
            payload,
        ),
    )

    def api_mailboxes_website_import():
        node_code = "online_mailbox_upload"
        node_label = "网站邮箱上传"

        def failure(message: str, code: str, status: int, provider_status: Any = None):
            public_message = f"网站邮箱上传 [{node_label}/{node_code}]：{message}"
            scope.logs.add(public_message, "error")
            payload = {
                "ok": False,
                "node_code": node_code,
                "node_label": node_label,
                "error_code": code,
                "error": public_message,
            }
            if provider_status is not None:
                payload["provider_status"] = provider_status
            return scope.module.jsonify(payload), status

        if scope.context.online_mailbox_client_factory is None:
            return failure("服务尚未配置", "online_mailbox_not_configured", 503)
        try:
            local = scope.context.read_local_config()
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
            snapshotter = getattr(scope.mailbox_admin, "online_mailbox_snapshot", None)
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
            client = scope.context.online_mailbox_client_factory(base_url, api_token)
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
            scope.logs.add(
                "网站邮箱上传完成: "
                f"新增 {response['created']}，更新 {response['updated']}，"
                f"重复 {response['duplicates']}，跳过 {response['skipped']}",
                "success",
            )
            return scope.module.jsonify(response)
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
            data = scope.module.request.get_json(silent=True) or {}
            result = scope.mailbox_admin.latest_code(data)
            if not result.get("ok"):
                return scope.module.jsonify(result), 400
            return scope.module.jsonify(result)
        except Exception as exc:
            payload = explicit_failure_payload(
                node_code="email_code_lookup", node_label="查询邮箱验证码",
                error_code="mailbox_latest_code_failed",
                cause=f"邮箱验证码读取异常（{type(exc).__name__}）",
                retryable=True, http_status=500,
            )
            scope.logs.add(f"[{payload['node_label']}/{payload['node_code']}] {payload['error']}", "error")
            return scope.module.jsonify(payload), 500

    def api_mailboxes_password():
        try:
            data = scope.module.request.get_json(silent=True) or {}
            if not isinstance(data, dict):
                return scope.module.jsonify(ok=False, error="请求必须是 JSON 对象"), 400
            result = scope.mailbox_admin.reveal_password(data.get("row_id"), data.get("line_no"))
            if result.get("ok"):
                return scope.module.jsonify(result)
            status = 409 if result.get("code") == "mailbox_row_stale" else 400
            return scope.module.jsonify(result), status
        except Exception as exc:
            payload = explicit_failure_payload(
                node_code="mailbox_password_reveal", node_label="读取邮箱密码",
                error_code="mailbox_password_reveal_failed",
                cause=f"邮箱密码存储读取异常（{type(exc).__name__}）", http_status=500,
            )
            return scope.module.jsonify(payload), 500

    def api_mailboxes_totp():
        try:
            data = scope.module.request.get_json(silent=True) or {}
            if not isinstance(data, dict):
                return scope.module.jsonify(ok=False, error="请求必须是 JSON 对象"), 400
            result = scope.mailbox_admin.reveal_totp(data.get("row_id"), data.get("line_no"))
            if result.get("ok"):
                return scope.module.jsonify(result)
            status = 409 if result.get("code") == "mailbox_row_stale" else 400
            return scope.module.jsonify(result), status
        except Exception as exc:
            payload = explicit_failure_payload(
                node_code="mailbox_totp_reveal", node_label="读取临时 2FA 验证码",
                error_code="mailbox_totp_reveal_failed",
                cause=f"2FA 密钥存储读取异常（{type(exc).__name__}）", http_status=500,
            )
            return scope.module.jsonify(payload), 500

    api_mailboxes_url = runtime_info_routes.mailbox_url
    api_runtime_task_mailbox_url = runtime_info_routes.runtime_task_mailbox_url
    api_runtime_task_latest_code = runtime_info_routes.runtime_task_latest_code
    api_runtime_task_mailbox_password = runtime_info_routes.runtime_task_mailbox_password
    api_runtime_task_mailbox_totp = runtime_info_routes.runtime_task_mailbox_totp

    def api_mailboxes_relogin():
        if not scope.context.lifecycle_lock.acquire(blocking=False):
            return ns["busy_response"]("另一个启动请求正在处理中")
        try:
            if scope.importer.status(scope.settings()).get("running"):
                return scope.module.jsonify(
                    ok=False,
                    code="run_already_active",
                    error="已有任务运行中，请先停止并等待任务结束",
                    state=ns["public_state"](),
                ), 409
            data = scope.module.request.get_json(silent=True) or {}
            if not isinstance(data, dict):
                return scope.module.jsonify(ok=False, code="relogin_rows_invalid", error="请求必须是 JSON 对象"), 400
            resolver = getattr(scope.mailbox_admin, "resolve_relogin_rows", None)
            if not callable(resolver):
                return scope.module.jsonify(
                    ok=False,
                    code="relogin_not_configured",
                    error="无手机号重登尚未配置",
                ), 503
            selected = resolver(data)
            if not isinstance(selected, Mapping):
                return scope.module.jsonify(
                    ok=False,
                    code="relogin_resolution_failed",
                    error=f"重登邮箱校验失败：服务返回了无效的 {type(selected).__name__} 结果",
                ), 502
            if not selected.get("ok"):
                code = str(selected.get("code") or "")
                status = 409 if code in {"mailbox_rows_stale", "relogin_not_required"} else 400
                return scope.module.jsonify(dict(selected)), status

            rows = [dict(item) for item in selected.get("items") or [] if isinstance(item, Mapping)]
            if not rows:
                return scope.module.jsonify(
                    ok=False,
                    code="relogin_rows_required",
                    error="请先勾选需要重登的 401/404 邮箱",
                ), 400
            run_config = dict(scope.store.load() or {})
            batch_started_at = int(time.time())
            run_config.update(
                run_mode="relogin",
                target_count=len(rows),
                batch_started_at=batch_started_at,
                batch_id=allocate_run_batch_id(scope.context, batch_started_at, scope.logs),
                _gptphone_relogin_rows=rows,
                _gptphone_run_mailbox_rows=[
                    {"row_id": row["row_id"], "line_no": row["line_no"]}
                    for row in rows
                ],
            )
            scope.context.sms_cost_ledger.clear()
            scope.importer.start(run_config)
            scope.logs.add(
                f"无手机号重登任务已启动: {len(rows)} 个邮箱，仅原位更新 SUB2",
                "success",
            )
            return scope.module.jsonify(
                ok=True,
                run_mode="relogin",
                batch_id=run_config["batch_id"],
                batch=(
                    scope.context.run_batch_manifest.get(run_config["batch_id"])
                    if scope.context.run_batch_manifest is not None
                    else None
                ),
                started=len(rows),
                mailboxes=scope.mailbox_admin.list_mailboxes(),
                state=ns["public_state"](),
            )
        except ValueError as exc:
            payload = explicit_failure_payload(
                node_code="relogin_start", node_label="启动重登任务",
                error_code="relogin_start_failed", cause=scope.context.safe_runtime_error(exc),
                state=ns["public_state"](), http_status=400,
            )
            return scope.module.jsonify(payload), 400
        except Exception as exc:
            payload = explicit_failure_payload(
                node_code="relogin_start", node_label="启动重登任务",
                error_code="relogin_start_failed",
                cause=f"重登任务启动异常（{type(exc).__name__}）",
                state=ns["public_state"](), retryable=True, http_status=500,
                action_hint="刷新邮箱状态并检查本地服务后重试。",
            )
            scope.logs.add(f"[{payload['node_label']}/{payload['node_code']}] {payload['error']}", "error")
            return scope.module.jsonify(payload), 500
        finally:
            scope.context.lifecycle_lock.release()

    api_mailboxes_openai_test = mailbox_batch_routes.openai_test
    # Keep the original URL as a compatibility alias for existing clients.
    api_mailboxes_sub2_test = mailbox_batch_routes.openai_test
    api_mailboxes_quota = mailbox_batch_routes.quota

    def mailbox_selection_error(result: Mapping[str, Any]):
        code = str(result.get("code") or "")
        status = 409 if code == "mailbox_rows_stale" else 400
        return scope.module.jsonify(dict(result)), status

    def request_json_object() -> dict[str, Any]:
        value = scope.module.request.get_json(silent=True) or {}
        return dict(value) if isinstance(value, Mapping) else {}

    def api_mailboxes_sub2_export():
        if scope.context.sub2_payload_builder is None:
            return scope.module.jsonify(ok=False, error="SUB2API 导出尚未配置"), 503
        try:
            selected = scope.mailbox_admin.selected_success_results(request_json_object())
            if not selected.get("ok"):
                return mailbox_selection_error(selected)
            accounts = []
            now = int(time.time())
            for item in selected.get("items") or []:
                payload = scope.context.sub2_payload_builder(item["document"])
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
                    "model_mapping": dict(SUB2_EXPORT_MODEL_MAPPING),
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
            return scope.module.jsonify(
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
                cause=public_message or scope.context.safe_runtime_error(exc),
                action_hint="确认所选账号结果包含完整且经过校验的 SUB2 Token。",
            )
            scope.logs.add(f"[SUB2API 导出/sub2_export] {payload['error']}", "error")
            return scope.module.jsonify(payload), 400

    api_run_batches = runtime_info_routes.run_batches
    api_run_batch = runtime_info_routes.run_batch

    sms_balance_routes = SmsBalanceRouteController(
        module=scope.module,
        context=scope.context,
        secrets_for=ns["route_secrets"],
    )
    api_sms_balances = sms_balance_routes.query

    local_config_routes = LocalConfigRouteController(
        module=scope.module,
        context=scope.context,
        importer=scope.importer,
        settings=scope.settings,
        public_state=ns["public_state"],
        busy_response=ns["busy_response"],
    )
    api_local_config = local_config_routes.get
    api_local_config_export = local_config_routes.export
    api_local_config_import = local_config_routes.import_config
    api_local_config_secret = local_config_routes.secret

    def api_notification_email_test():
        try:
            data = scope.module.request.get_json(silent=True) or {}
            if not isinstance(data, dict):
                return scope.module.jsonify(ok=False, error="配置必须是 JSON 对象"), 400
            result = scope.context.test_email_notification(data)
            return scope.module.jsonify(ok=True, notification=result, state=ns["public_state"]())
        except (ValueError, NotificationConfigError) as exc:
            payload = explicit_failure_payload(
                node_code="notification_test", node_label="测试邮件通知",
                error_code="notification_test_failed", cause=scope.context.safe_runtime_error(exc),
                secrets=ns["route_secrets"](data), state=ns["public_state"](), http_status=400,
                action_hint="检查 SMTP 地址、授权码和收件地址。",
            )
            return scope.module.jsonify(payload), 400
        except Exception as exc:
            payload = explicit_failure_payload(
                node_code="notification_test",
                node_label="测试邮件通知",
                error_code="notification_test_failed",
                cause=scope.context.safe_runtime_error(exc),
                secrets=ns["route_secrets"](data),
                state=ns["public_state"](),
                retryable=True,
                http_status=502,
                action_hint="检查 SMTP 地址、授权码、收件地址和当前网络。",
            )
            scope.logs.add(f"[测试邮件通知/notification_test] {payload['error']}", "error")
            return scope.module.jsonify(payload), 502

    try:
        from .free_account_routes import FreeAccountRouteController
    except ImportError:
        from free_account_routes import FreeAccountRouteController  # type: ignore[no-redef]
    free_account_routes = FreeAccountRouteController(
        module=scope.module,
        manager=scope.free_manager,
        config_store=scope.free_config_store,
        free_state=ns["free_state"],
        error_response=ns["free_error_response"],
    )

    # Rebind owns an independent mailbox pool and task state.  Construct it
    # beside the Free registration manager, but keep its worker and routes
    # isolated from the registration driver lifecycle.
    try:
        from .free_rebind_runtime import FreeRebindService
        from .free_rebind_routes import FreeRebindRouteController
    except ImportError:
        from free_rebind_runtime import FreeRebindService  # type: ignore[no-redef]
        from free_rebind_routes import FreeRebindRouteController  # type: ignore[no-redef]
    rebind_root = scope.context.free_data_dir
    if rebind_root is None and scope.free_manager is not None:
        rebind_root = getattr(scope.free_manager, "data_dir", None)
    rebind_config_provider = getattr(scope.free_config_store, "load", None) if scope.free_config_store is not None else None
    free_rebind_service = (
        FreeRebindService(
            rebind_root,
            free_manager=scope.free_manager,
            config_provider=rebind_config_provider,
            log_fn=getattr(scope.free_manager, "_log", None),
        )
        if scope.free_manager is not None and rebind_root is not None
        else None
    )
    if free_rebind_service is not None:
        scope.app.extensions["gptphone_free_rebind"] = free_rebind_service
    free_rebind_routes = FreeRebindRouteController(
        module=scope.module,
        service=free_rebind_service,
        error_response=ns["free_error_response"],
    )
    diagnostic_routes = None
    if scope.diagnostic_store is not None:
        try:
            from .diagnostic_routes import DiagnosticRouteController
        except ImportError:  # pragma: no cover
            from diagnostic_routes import DiagnosticRouteController  # type: ignore[no-redef]
        diagnostic_routes = DiagnosticRouteController(module=scope.module, store=scope.diagnostic_store)
    parser_sample_routes = MailboxParserSampleRouteController(
        module=scope.module,
        ordinary_store=scope.context.mailbox_parser_sample_store,
        free_store=scope.context.free_mailbox_parser_sample_store,
    )
    return {
        "mailbox_manager": mailbox_manager,
        "api_mailboxes": api_mailboxes,
        "api_remail_profile": api_remail_profile,
        "api_remail_config": api_remail_config,
        "api_remail_key": api_remail_key,
        "api_remail_projects": api_remail_projects,
        "api_remail_wallet": api_remail_wallet,
        "api_remail_purchase": api_remail_purchase,
        "api_remail_orders": api_remail_orders,
        "api_remail_import_orders": api_remail_import_orders,
        "api_remail_hide_orders": api_remail_hide_orders,
        "diagnostic_routes": diagnostic_routes,
        "free_account_routes": free_account_routes,
        "free_rebind_routes": free_rebind_routes,
        "mailbox_mutation_routes": mailbox_mutation_routes,
        "api_mailboxes_website_import": api_mailboxes_website_import,
        "api_mailboxes_latest_code": api_mailboxes_latest_code,
        "api_mailboxes_password": api_mailboxes_password,
        "api_mailboxes_totp": api_mailboxes_totp,
        "api_mailboxes_url": api_mailboxes_url,
        "api_runtime_task_mailbox_url": api_runtime_task_mailbox_url,
        "api_runtime_task_latest_code": api_runtime_task_latest_code,
        "api_runtime_task_mailbox_password": api_runtime_task_mailbox_password,
        "api_runtime_task_mailbox_totp": api_runtime_task_mailbox_totp,
        "api_mailboxes_relogin": api_mailboxes_relogin,
        "api_mailbox_url_test": api_mailbox_url_test,
        "parser_sample_routes": parser_sample_routes,
        "api_mailboxes_sub2_test": api_mailboxes_sub2_test,
        "api_mailboxes_openai_test": api_mailboxes_openai_test,
        "api_mailboxes_quota": api_mailboxes_quota,
        "api_run_batches": api_run_batches,
        "api_run_batch": api_run_batch,
        "api_mailboxes_sub2_export": api_mailboxes_sub2_export,
        "api_local_config": api_local_config,
        "api_sms_balances": api_sms_balances,
        "api_local_config_export": api_local_config_export,
        "api_local_config_import": api_local_config_import,
        "api_local_config_secret": api_local_config_secret,
        "api_notification_email_test": api_notification_email_test,
    }


def build_route_sections(scope: RouteScope) -> dict[str, Any]:
    """Assemble every dashboard view in the original closure construction order."""
    ns: dict[str, Any] = {}
    ns.update(build_core_routes(scope, ns))
    ns.update(build_free_routes(scope, ns))
    ns.update(build_remail_routes(scope, ns))
    return ns


__all__ = [
    "RouteScope",
    "build_route_sections",
]
