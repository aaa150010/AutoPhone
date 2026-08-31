"""Isolated Free mailbox and proxy pool HTTP routes."""

from __future__ import annotations

from collections.abc import Mapping
import inspect
from typing import Any, Callable


def signature_accepts_call(
    callback: Callable[..., Any],
    *args: Any,
    **kwargs: Any,
) -> bool | None:
    """Check compatibility without invoking a potentially stateful callback."""
    try:
        signature = inspect.signature(callback)
    except (TypeError, ValueError):
        return None
    try:
        signature.bind(*args, **kwargs)
    except TypeError:
        return False
    return True


def import_free_proxies(
    importer: Callable[..., Any],
    content: str,
    *,
    country: str | None,
    group: str | None,
    scheme: str | None,
    source_label: str | None = None,
) -> Any:
    """Call modern or legacy proxy importers exactly once."""
    options = {"country": country, "group": group, "scheme": scheme}
    if source_label:
        options["source_label"] = source_label
    accepts_options = signature_accepts_call(importer, content, **options)
    if accepts_options is True:
        return importer(content, **options)
    # Older stores may support the original metadata keyword set but not the
    # optional provider label.  Inspect first so an internal TypeError raised
    # by the importer is never mistaken for a signature mismatch or retried.
    options_without_label = dict(options)
    options_without_label.pop("source_label", None)
    if signature_accepts_call(importer, content, **options_without_label) is True:
        return importer(content, **options_without_label)
    if signature_accepts_call(importer, content) is True:
        return importer(content)
    if accepts_options is None:
        try:
            return importer(content, **options)
        except TypeError:
            # Older stores do not know the optional source label.
            options.pop("source_label", None)
            return importer(content, **options)
    raise TypeError("Free 代理导入器签名不兼容")


def import_free_mailboxes(
    importer: Callable[..., Any],
    content: str,
    *,
    join_current_batch: bool = False,
    config: Mapping[str, Any] | None = None,
) -> Any:
    """Invoke a Free mailbox importer using one inspected call shape.

    The SQLite-backed manager accepts the ``join_current_batch`` and ``config``
    keyword arguments, while integrations written against the original route
    expose only ``import_mailboxes(content)``.  Inspect the callable before
    invoking it so a signature mismatch never causes a second stateful import;
    an importer which raises internally is called exactly once and its error is
    allowed to propagate to the route failure mapper.
    """
    modern_kwargs = {
        "join_current_batch": bool(join_current_batch),
        "config": config if isinstance(config, Mapping) else {},
    }
    candidates = (
        modern_kwargs,
        {"join_current_batch": bool(join_current_batch)},
        {"config": config if isinstance(config, Mapping) else {}},
        {},
    )
    for kwargs in candidates:
        accepts = signature_accepts_call(importer, content, **kwargs)
        if accepts is True:
            return importer(content, **kwargs)
        if accepts is None:
            # Builtins and some proxy callables do not expose a signature.  A
            # single modern invocation preserves the current manager contract;
            # importantly, an internal TypeError is not retried as legacy.
            return importer(content, **modern_kwargs)
    raise TypeError("Free 邮箱导入器签名不兼容")


def _request_row_ids(data: Any) -> list[str]:
    """Normalize an explicit row selection without turning invalid input into all rows."""
    if not isinstance(data, Mapping) or not isinstance(data.get("row_ids"), list):
        return []
    return list(dict.fromkeys(
        str(value or "").strip().lower()
        for value in data.get("row_ids") or []
        if str(value or "").strip()
    ))


class FreePoolRouteController:
    """Routes that own the isolated Free mailbox and proxy pools."""

    def __init__(
        self,
        *,
        module: Any,
        manager: Any,
        config_store: Any,
        state: Callable[[], Mapping[str, Any]],
        mutation_conflict: Callable[[str], Any],
        error_response: Callable[..., Any],
        failure_response: Callable[..., Any],
        request_lock: Any,
        ordinary_mailbox_import: Callable[[str], Mapping[str, Any]] | None = None,
    ) -> None:
        self.module = module
        self.manager = manager
        self.config_store = config_store
        self.state = state
        self.mutation_conflict = mutation_conflict
        self.error_response = error_response
        self.failure_response = failure_response
        self.request_lock = request_lock
        self.ordinary_mailbox_import = ordinary_mailbox_import

    def mailboxes(self):
        if self.manager is None:
            return self.module.jsonify(ok=False, error="Free 注册服务尚未初始化"), 503
        try:
            counts = self.manager.pool.counts() if callable(getattr(self.manager.pool, "counts", None)) else {}
            proxies = self.manager.proxies.public() if callable(getattr(self.manager.proxies, "public", None)) else {}
            return self.module.jsonify(
                ok=True,
                pool="free",
                counts=counts,
                proxies=proxies,
                rows=self.manager.pool.public_rows(),
                state=self.state(),
            )
        except Exception as exc:
            return self.failure_response(
                exc,
                default_code="free_mailboxes_read",
                default_label="读取 Free 邮箱池",
                status=503,
            )

    def pool_import(self):
        if self.manager is None:
            return self.module.jsonify(ok=False, error="Free 注册服务尚未初始化"), 503
        data = self.module.request.get_json(silent=True) or {}
        if not isinstance(data, Mapping):
            return self.error_response(
                ValueError("请求必须是 JSON 对象"),
                default_code="free_pool",
                default_label="Free 邮箱池",
            )
        try:
            content = str(data.get("pool_content") or "")
            join_current_batch = bool(data.get("join_current_batch", False))
            importer = getattr(self.manager, "import_mailboxes", None)
            if callable(importer):
                # The modern manager owns the running-import policy.  Read
                # state first so a broken state store fails closed before any
                # mailbox mutation; unlike legacy managers, a healthy modern
                # manager may accept imports while a batch is running.
                try:
                    current_state = self.state()
                except Exception as exc:
                    return self.failure_response(
                        exc,
                        default_code="free_state_read",
                        default_label="读取 Free 运行状态",
                        status=503,
                    )
                result = import_free_mailboxes(
                    importer,
                    content,
                    join_current_batch=join_current_batch,
                    config=self.config_store.load() if self.config_store is not None else {},
                )
                # Modern managers return a mapping; older managers returned a
                # ``(imported, skipped)`` tuple or a single count.  Normalize
                # those shapes at this boundary so the HTTP contract remains
                # stable without invoking an importer twice.
                if isinstance(result, Mapping):
                    result_payload = result
                elif isinstance(result, (tuple, list)):
                    result_payload = {
                        "imported": result[0] if len(result) > 0 else 0,
                        "skipped": result[1] if len(result) > 1 else 0,
                    }
                else:
                    result_payload = {"imported": result, "skipped": 0}
                count = int(result_payload.get("imported") or 0)
                skipped = int(result_payload.get("skipped") or 0)
                # Import may append tasks to the active batch, so the state
                # captured before mutation is stale.  Return a fresh snapshot
                # that accurately reflects queued/active slots and pool
                # counts.
                try:
                    current_state = self.state()
                except Exception as exc:
                    return self.failure_response(
                        exc,
                        default_code="free_state_read",
                        default_label="读取 Free 运行状态",
                        status=503,
                    )
                return self.module.jsonify(
                    ok=True,
                    imported=count,
                    skipped=skipped,
                    queued=int(result_payload.get("queued") or 0),
                    active_batch_joined=int(result_payload.get("active_batch_joined") or 0),
                    next_batch=int(result_payload.get("next_batch") or 0),
                    reason=str(result_payload.get("reason") or ""),
                    skipped_items=result_payload.get("skipped_items") or [],
                    rows=self.manager.pool.public_rows(),
                    state=current_state,
                )
            conflict = self.mutation_conflict("导入 Free 邮箱")
            if conflict is not None:
                return conflict
            importer_with_stats = getattr(self.manager.pool, "import_text_with_stats", None)
            if callable(importer_with_stats):
                count, skipped = importer_with_stats(content)
            else:
                count = self.manager.pool.import_text(content)
                skipped = 0
            return self.module.jsonify(
                ok=True,
                imported=count,
                skipped=skipped,
                queued=0,
                active_batch_joined=0,
                rows=self.manager.pool.public_rows(),
                state=self.state(),
            )
        except Exception as exc:
            return self.error_response(exc, default_code="free_pool", default_label="Free 邮箱池")

    def pool_delete(self):
        if self.manager is None:
            return self.module.jsonify(ok=False, error="Free 注册服务尚未初始化"), 503
        conflict = self.mutation_conflict("删除 Free 邮箱")
        if conflict is not None:
            return conflict
        data = self.module.request.get_json(silent=True) or {}
        if not isinstance(data, Mapping):
            return self.error_response(
                ValueError("请求必须是 JSON 对象"),
                default_code="free_pool_delete",
                default_label="删除 Free 邮箱",
            )
        row_ids = data.get("row_ids")
        if not isinstance(row_ids, list):
            return self.error_response(
                ValueError("请选择要删除的 Free 邮箱"),
                default_code="free_pool_delete",
                default_label="删除 Free 邮箱",
            )
        try:
            deleted = self.manager.pool.delete([str(value or "") for value in row_ids])
            return self.module.jsonify(
                ok=True,
                deleted=deleted,
                rows=self.manager.pool.public_rows(),
            )
        except Exception as exc:
            return self.error_response(
                exc,
                default_code="free_pool_delete",
                default_label="删除 Free 邮箱",
            )

    def proxy_import(self):
        if self.manager is None:
            return self.module.jsonify(ok=False, error="Free 注册服务尚未初始化"), 503
        conflict = self.mutation_conflict("导入 Free 代理")
        if conflict is not None:
            return conflict
        data = self.module.request.get_json(silent=True) or {}
        if not isinstance(data, Mapping):
            return self.error_response(
                ValueError("请求必须是 JSON 对象"),
                default_code="free_proxy_pool",
                default_label="Free 代理池",
            )
        try:
            count = import_free_proxies(
                self.manager.proxies.import_text,
                str(data.get("proxy_content") or ""),
                country=str(data.get("country") or "").strip().upper() or None,
                group=str(data.get("group") or "").strip() or None,
                scheme=str(data.get("scheme") or "").strip().lower() or None,
                source_label=str(data.get("source_label") or data.get("provider") or "").strip()[:40] or None,
            )
            public = self.manager.proxies.public() if callable(getattr(self.manager.proxies, "public", None)) else None
            return self.module.jsonify(
                ok=True,
                imported=count,
                **({"proxies": public} if public is not None else {}),
            )
        except Exception as exc:
            return self.error_response(
                exc,
                default_code="free_proxy_pool",
                default_label="Free 代理池",
            )

    def proxy_preflight(self):
        if self.manager is None or self.config_store is None:
            return self.module.jsonify(ok=False, error="Free 注册服务尚未初始化"), 503
        conflict = self.mutation_conflict("执行 Free 代理预检")
        if conflict is not None:
            return conflict
        if not self.request_lock.acquire(blocking=False):
            return self.module.jsonify(
                ok=False,
                error="Free 配置、预检或启动请求正在处理中",
                state=self.state(),
            ), 409
        try:
            data = self.module.request.get_json(silent=True) or {}
            if not isinstance(data, Mapping):
                return self.error_response(
                    ValueError("请求必须是 JSON 对象"),
                    default_code="free_proxy_preflight",
                    default_label="Free 代理预检",
                )
            current = self.config_store.load()
            probe_config = self.config_store.normalize(
                {
                    "proxy_probe_url": data.get("proxy_probe_url") or current.get("proxy_probe_url"),
                    "proxy_tls_verify": data.get("proxy_tls_verify", current.get("proxy_tls_verify", True)),
                    "proxy_tls_compat_fallback": data.get(
                        "proxy_tls_compat_fallback",
                        current.get("proxy_tls_compat_fallback", True),
                    ),
                    "proxy_socks5_dns_mode": data.get(
                        "proxy_socks5_dns_mode",
                        current.get("proxy_socks5_dns_mode", "remote"),
                    ),
                },
                previous=current,
            )
            result = self.manager.preflight_proxies(
                proxy_content=str(data.get("proxy_content") or ""),
                probe_url=str(probe_config.get("proxy_probe_url") or "https://chatgpt.com/"),
                driver=str(data.get("driver") or "protocol"),
                country=str(data.get("country") or "").strip().upper() or None,
                group=str(data.get("group") or "").strip() or None,
                scheme=str(data.get("scheme") or "").strip().lower() or None,
                tls_verify=bool(probe_config.get("proxy_tls_verify", True)),
                tls_compat_fallback=bool(probe_config.get("proxy_tls_compat_fallback", True)),
                socks5_dns_mode=str(probe_config.get("proxy_socks5_dns_mode") or "remote"),
                layered_probe=bool(data.get("layered_probe", False)),
            )
            payload: dict[str, Any] = {"ok": True, "result": result}
            if isinstance(result, Mapping):
                # A mixed proxy preflight is a successful diagnostic request,
                # not an HTTP route failure. Expose its batch incident and
                # canonical aggregate failure alongside the detailed result so
                # clients can offer Log Center actions without parsing rows.
                incident_id = str(result.get("incident_id") or "").strip()
                failure = result.get("failure")
                if incident_id:
                    payload["incident_id"] = incident_id
                if isinstance(failure, Mapping):
                    payload["failure"] = dict(failure)
            return self.module.jsonify(**payload)
        except Exception as exc:
            return self.failure_response(
                exc,
                default_code="free_proxy_preflight",
                default_label="Free 代理预检",
                status=502 if not isinstance(exc, ValueError) else 400,
            )
        finally:
            self.request_lock.release()

    def proxies(self):
        if self.manager is None:
            return self.module.jsonify(ok=False, error="Free 注册服务尚未初始化"), 503
        try:
            return self.module.jsonify(ok=True, proxies=self.manager.proxies.public())
        except Exception as exc:
            return self.failure_response(
                exc,
                default_code="free_proxies_read",
                default_label="读取 Free 代理池",
                status=503,
            )

    def proxy_group(self):
        if self.manager is None:
            return self.module.jsonify(ok=False, error="Free 注册服务尚未初始化"), 503
        conflict = self.mutation_conflict("修改 Free 代理分组")
        if conflict is not None:
            return conflict
        data = self.module.request.get_json(silent=True) or {}
        if not isinstance(data, Mapping):
            return self.error_response(
                ValueError("请求必须是 JSON 对象"),
                default_code="free_proxy_group",
                default_label="更新 Free 代理分组",
            )
        try:
            # Free registration uses one shared healthy_random pool. Keep the
            # historical endpoint callable for old clients, but do not let a
            # country/group mutation become a hidden allocation or disable
            # strategy.
            updater = getattr(self.manager.proxies, "update_group", None)
            result = updater("", "") if callable(updater) else {"matched": 0, "modified": 0}
            return self.module.jsonify(
                ok=True,
                result=result,
                deprecated=True,
                proxies=self.manager.proxies.public(),
            )
        except Exception as exc:
            return self.error_response(
                exc,
                default_code="free_proxy_group",
                default_label="更新 Free 代理分组",
            )

    def proxy_group_delete(self):
        if self.manager is None:
            return self.module.jsonify(ok=False, error="Free 注册服务尚未初始化"), 503
        conflict = self.mutation_conflict("删除 Free 代理分组")
        if conflict is not None:
            return conflict
        data = self.module.request.get_json(silent=True) or {}
        if not isinstance(data, Mapping):
            return self.error_response(
                ValueError("请求必须是 JSON 对象"),
                default_code="free_proxy_group_delete",
                default_label="删除 Free 代理分组",
            )
        try:
            deleter = getattr(self.manager.proxies, "delete_group", None)
            deleted = int(deleter("", "")) if callable(deleter) else 0
            return self.module.jsonify(
                ok=True,
                deleted=deleted,
                deprecated=True,
                proxies=self.manager.proxies.public(),
            )
        except Exception as exc:
            return self.error_response(
                exc,
                default_code="free_proxy_group_delete",
                default_label="删除 Free 代理分组",
            )

    def pool_status(self, status: str):
        if self.manager is None:
            return self.module.jsonify(ok=False, error="Free 注册服务尚未初始化"), 503
        conflict = self.mutation_conflict("修改 Free 邮箱状态")
        if conflict is not None:
            return conflict
        data = self.module.request.get_json(silent=True) or {}
        row_ids = data.get("row_ids") if isinstance(data, Mapping) else None
        if not isinstance(row_ids, list):
            return self.error_response(
                ValueError("请选择 Free 邮箱"),
                default_code="free_pool_status",
                default_label="更新 Free 邮箱状态",
            )
        try:
            changed = self.manager.pool.set_status(row_ids, status)
            return self.module.jsonify(
                ok=True,
                updated=changed,
                counts=self.manager.pool.counts(),
                rows=self.manager.pool.public_rows(),
            )
        except Exception as exc:
            return self.error_response(
                exc,
                default_code="free_pool_status",
                default_label="更新 Free 邮箱状态",
            )

    def pool_unavailable(self):
        return self.pool_status("unavailable")

    def pool_draft(self):
        return self.pool_status("draft")

    def pool_restore(self):
        return self.pool_status("available")

    def export(self):
        if self.manager is None:
            return self.module.jsonify(ok=False, error="Free 注册服务尚未初始化"), 503
        data = self.module.request.get_json(silent=True) or {}
        row_ids = data.get("row_ids") if isinstance(data, Mapping) and isinstance(data.get("row_ids"), list) else []
        try:
            content = self.manager.pool.export_success(row_ids)
            response = self.module.Response(content, mimetype="text/plain")
            response.headers["Content-Disposition"] = "attachment; filename=free-register-success.txt"
            return response
        except Exception as exc:
            return self.failure_response(
                exc,
                default_code="free_export",
                default_label="导出 Free 注册结果",
                status=503,
            )

    def transfer(self):
        """Explicitly copy selected Free rows into the ordinary mailbox pool."""
        if self.manager is None:
            return self.module.jsonify(ok=False, error="Free 注册服务尚未初始化"), 503
        if not callable(self.ordinary_mailbox_import):
            return self.module.jsonify(ok=False, error="普通接码邮箱池尚未初始化"), 503
        conflict = self.mutation_conflict("传输 Free 邮箱")
        if conflict is not None:
            return conflict
        if not self.request_lock.acquire(blocking=False):
            return self.module.jsonify(
                ok=False,
                error="Free 配置、导入或传输请求正在处理中",
            ), 409
        try:
            data = self.module.request.get_json(silent=True) or {}
            row_ids = _request_row_ids(data)
            if not row_ids:
                return self.error_response(
                    ValueError("请选择要传输的 Free 邮箱"),
                    default_code="free_mailbox_transfer",
                    default_label="传输 Free 邮箱",
                )
            prepared = self.manager.pool.build_transfer_content(row_ids)
            content = str(prepared.get("content") or "")
            if not content:
                return self.module.jsonify(
                    ok=True,
                    imported=0,
                    skipped=int(prepared.get("skipped") or 0),
                    skipped_items=list(prepared.get("skipped_items") or []),
                    prepared=0,
                    ordinary_mailboxes_refresh_required=False,
                )
            ordinary = self.ordinary_mailbox_import(content)
            ordinary = dict(ordinary) if isinstance(ordinary, Mapping) else {}
            imported = max(0, int(ordinary.get("imported") or 0))
            ordinary_skipped = max(0, int(ordinary.get("skipped") or 0))
            duplicate_only = not ordinary.get("ok") and "没有新增邮箱" in str(ordinary.get("error") or "")
            if duplicate_only:
                ordinary_skipped = max(
                    ordinary_skipped,
                    max(0, int(prepared.get("prepared") or 0) - imported),
                )
            if not ordinary.get("ok") and not duplicate_only:
                raise ValueError(str(ordinary.get("error") or "普通邮箱池导入失败"))
            skipped_items = list(prepared.get("skipped_items") or [])
            if ordinary_skipped:
                skipped_items.append({
                    "row_id": "",
                    "email": "",
                    "reason": f"普通接码邮箱池跳过重复 {ordinary_skipped} 条",
                })
            return self.module.jsonify(
                ok=True,
                imported=imported,
                skipped=ordinary_skipped + int(prepared.get("skipped") or 0),
                skipped_items=skipped_items,
                prepared=int(prepared.get("prepared") or 0),
                ordinary_mailboxes_refresh_required=bool(imported),
            )
        except Exception as exc:
            return self.error_response(
                exc,
                default_code="free_mailbox_transfer",
                default_label="传输 Free 邮箱",
            )
        finally:
            self.request_lock.release()

    def format(self):
        """Return explicitly requested sensitive Free rows for clipboard copy."""
        if self.manager is None:
            return self.module.jsonify(ok=False, error="Free 注册服务尚未初始化"), 503
        conflict = self.mutation_conflict("复制 Free 邮箱格式")
        if conflict is not None:
            return conflict
        if not self.request_lock.acquire(blocking=False):
            return self.module.jsonify(ok=False, error="Free 配置、导入或复制请求正在处理中"), 409
        try:
            data = self.module.request.get_json(silent=True) or {}
            row_ids = _request_row_ids(data)
            if not row_ids:
                return self.error_response(
                    ValueError("请选择要复制的 Free 邮箱"),
                    default_code="free_mailbox_format",
                    default_label="复制 Free 邮箱格式",
                )
            mode = str(data.get("mode") or "full").strip().lower()
            if mode not in {"mailbox", "full"}:
                return self.error_response(
                    ValueError("复制格式无效"),
                    default_code="free_mailbox_format",
                    default_label="复制 Free 邮箱格式",
                )
            prepared = self.manager.pool.build_transfer_content(
                row_ids,
                include_password=mode == "full",
            )
            content = str(prepared.get("content") or "")
            if not content:
                return self.module.jsonify(
                    ok=True,
                    mode=mode,
                    content="",
                    prepared=0,
                    skipped=int(prepared.get("skipped") or 0),
                    skipped_items=list(prepared.get("skipped_items") or []),
                )
            return self.module.jsonify(
                ok=True,
                mode=mode,
                content=content,
                prepared=int(prepared.get("prepared") or 0),
                skipped=int(prepared.get("skipped") or 0),
                skipped_items=list(prepared.get("skipped_items") or []),
            )
        except Exception as exc:
            return self.error_response(
                exc,
                default_code="free_mailbox_format",
                default_label="复制 Free 邮箱格式",
            )
        finally:
            self.request_lock.release()

    def secret(self):
        if self.manager is None:
            return self.module.jsonify(ok=False, error="Free 注册服务尚未初始化"), 503
        data = self.module.request.get_json(silent=True) or {}
        if not isinstance(data, Mapping):
            return self.error_response(
                ValueError("请求必须是 JSON 对象"),
                default_code="free_secret",
                default_label="读取 Free 敏感字段",
            )
        raw_task_ids = data.get("task_ids") if isinstance(data.get("task_ids"), list) else [data.get("task_id")]
        task_ids = [str(value).strip() for value in raw_task_ids if str(value or "").strip()]
        kind = str(data.get("kind") or "").strip().lower()
        if kind not in {"token", "password", "totp", "proxy", "credential", "email"}:
            return self.error_response(
                ValueError("敏感字段类型无效"),
                default_code="free_secret",
                default_label="读取 Free 敏感字段",
            )
        raw_row_ids = data.get("row_ids") if isinstance(data.get("row_ids"), list) else [data.get("row_id")]
        row_ids = [str(value).strip() for value in raw_row_ids if str(value or "").strip()]
        try:
            value = self.manager.secret(task_ids, kind, row_ids=row_ids)
            return self.module.jsonify(ok=True, kind=kind, value=value)
        except Exception as exc:
            status = 400 if isinstance(exc, ValueError) or getattr(exc, "retryable", None) is False else 503
            return self.failure_response(
                exc,
                default_code="free_secret",
                default_label="读取 Free 敏感字段",
                status=status,
            )

    def totp(self):
        """Return only the current temporary TOTP code for selected rows."""
        if self.manager is None:
            return self.module.jsonify(ok=False, error="Free 注册服务尚未初始化"), 503
        data = self.module.request.get_json(silent=True) or {}
        if not isinstance(data, Mapping):
            return self.error_response(
                ValueError("请求必须是 JSON 对象"),
                default_code="free_totp",
                default_label="读取 Free 临时 2FA 验证码",
            )
        raw_task_ids = data.get("task_ids") if isinstance(data.get("task_ids"), list) else [data.get("task_id")]
        task_ids = [str(value).strip() for value in raw_task_ids if str(value or "").strip()]
        raw_row_ids = data.get("row_ids") if isinstance(data.get("row_ids"), list) else [data.get("row_id")]
        row_ids = [str(value).strip() for value in raw_row_ids if str(value or "").strip()]
        try:
            result = self.manager.temporary_totp(task_ids, row_ids=row_ids)
            return self.module.jsonify(ok=True, kind="totp", **result)
        except Exception as exc:
            status = 400 if isinstance(exc, ValueError) or getattr(exc, "retryable", None) is False else 503
            return self.failure_response(
                exc,
                default_code="free_totp",
                default_label="读取 Free 临时 2FA 验证码",
                status=status,
            )

    def routes(self):
        return (
            ("/api/free/mailboxes", "api_free_mailboxes", self.mailboxes, ["GET"]),
            ("/api/free/mailboxes/import", "api_free_pool_import", self.pool_import, ["POST"]),
            ("/api/free/mailboxes/delete", "api_free_pool_delete", self.pool_delete, ["POST"]),
            ("/api/free/mailboxes/unavailable", "api_free_pool_unavailable", self.pool_unavailable, ["POST"]),
            ("/api/free/mailboxes/draft", "api_free_pool_draft", self.pool_draft, ["POST"]),
            ("/api/free/mailboxes/restore", "api_free_pool_restore", self.pool_restore, ["POST"]),
            ("/api/free/mailboxes/export", "api_free_export", self.export, ["POST"]),
            ("/api/free/mailboxes/transfer", "api_free_mailbox_transfer", self.transfer, ["POST"]),
            ("/api/free/mailboxes/format", "api_free_mailbox_format", self.format, ["POST"]),
            ("/api/free/proxies/import", "api_free_proxy_import", self.proxy_import, ["POST"]),
            ("/api/free/proxies/preflight", "api_free_proxy_preflight", self.proxy_preflight, ["POST"]),
            ("/api/free/proxies", "api_free_proxies", self.proxies, ["GET"]),
            ("/api/free/proxies/group", "api_free_proxy_group", self.proxy_group, ["POST"]),
            ("/api/free/proxies/group/delete", "api_free_proxy_group_delete", self.proxy_group_delete, ["POST"]),
            ("/api/free/secrets", "api_free_secret", self.secret, ["POST"]),
            ("/api/free/totp", "api_free_totp", self.totp, ["POST"]),
        )


__all__ = [
    "FreePoolRouteController",
    "import_free_mailboxes",
    "import_free_proxies",
    "signature_accepts_call",
]
