"""Preflight and proxy-probe mixin for FreeRegisterManager.

Split out of ``free_register_runtime.py``; the manager composes this mixin so
the responsibility band keeps its own module.  Methods rely on attributes and
methods defined by the manager (``self._lock``, ``self.pool``, ``self.proxies``,
``self.public_state`` ...).  Module-level globals referenced by the methods
resolve through the composing runtime module via ``_runtime_module()`` so
existing tests can keep patching ``mac_overrides.free_register_runtime.<name>``.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Mapping
from urllib.parse import urlsplit

try:
    from .diagnostic_writer import DiagnosticEventWriter, LogContext
    from .free_proxy_health import is_proxy_health_failure
    from .free_register_common import (
        ProxyBinding,
        FreeRegisterError,
        fingerprint as _fingerprint,
        mask_proxy as _mask_proxy,
        proxy_transport_value,
        safe_log_message as _safe_log_message,
    )
    from .free_account_service import password_retry_allowed
    from .free_failure_runtime import (
        canonical_failure,
        exception_to_failure,
        has_account_result,
        merge_account_result_fields,
        sanitize_failure_text,
    )
    from .free_runtime_info import runtime_info
except ImportError:  # macOS launcher imports overrides as top-level modules.
    from diagnostic_writer import DiagnosticEventWriter, LogContext  # type: ignore[no-redef]
    from free_proxy_health import is_proxy_health_failure  # type: ignore[no-redef]
    from free_register_common import (  # type: ignore[no-redef]
        ProxyBinding,
        FreeRegisterError,
        fingerprint as _fingerprint,
        mask_proxy as _mask_proxy,
        proxy_transport_value,
        safe_log_message as _safe_log_message,
    )
    from free_account_service import password_retry_allowed  # type: ignore[no-redef]
    from free_failure_runtime import (  # type: ignore[no-redef]
        canonical_failure,
        exception_to_failure,
        has_account_result,
        merge_account_result_fields,
        sanitize_failure_text,
    )
    from free_runtime_info import runtime_info  # type: ignore[no-redef]



try:
    from .quiet_note import note_stderr
except ImportError:  # pragma: no cover - top-level recovery import
    from quiet_note import note_stderr  # type: ignore[no-redef]

def _note_stderr(where: str, exc: BaseException) -> None:
    note_stderr('free_register_preflight', where, exc)


def _runtime_module() -> Any:
    """Resolve the composing runtime module lazily.

    Patchable globals such as ``PriorityExecutor`` and ``CamoufoxRunner`` stay
    addressable on ``free_register_runtime`` so existing tests and integrations
    can patch them there; resolving through the module keeps that contract
    intact.
    """
    try:
        from . import free_register_runtime as runtime
    except ImportError:  # macOS launcher imports overrides as top-level modules.
        import free_register_runtime as runtime  # type: ignore[no-redef]
    return runtime


class FreeRegisterPreflightMixin:
    """Methods moved verbatim from the FreeRegisterManager band."""





    def preflight(self, config: Mapping[str, Any], *, proxy_content: str = "") -> dict[str, Any]:
        with self._lock:
            if self.public_state().get("running"):
                raise FreeRegisterError(
                    "free_run_preflight",
                    "预检 Free 注册",
                    "Free 注册任务运行中，暂不能执行批次预检",
                    retryable=False,
                )
        driver = str(config.get("driver") or "protocol").strip().lower()
        if driver not in {"protocol", "camoufox"}:
            raise FreeRegisterError("free_config", "Free 注册预检", "Free 注册链路无效", retryable=False)
        protocol_result = {}
        if driver == "protocol" and not self._custom_runner:
            protocol_result = self.protocol_preflight(config)
        self.proxies.configure_policy(
            failure_threshold=int(config.get("proxy_failure_threshold") or 2),
            quarantine_seconds=int(config.get("proxy_quarantine_seconds") or 600),
            health_probe_ttl_seconds=int(config["proxy_health_probe_ttl_seconds"]) if "proxy_health_probe_ttl_seconds" in config else 0,
            tls_verify=bool(config.get("proxy_tls_verify", True)),
            tls_compat_fallback=bool(config.get("proxy_tls_compat_fallback", True)),
            socks5_dns_mode=str(config.get("proxy_socks5_dns_mode") or "remote"),
            allocation_mode="healthy_random",
        )
        available = self._available_count()
        requested = max(1, min(int(config.get("target_count") or 1), 200))
        target = min(requested, available)
        if target <= 0:
            raise FreeRegisterError("free_pool_preflight", "Free 邮箱池预检", "Free 邮箱池没有可用邮箱", retryable=False)
        bindings = self.proxies.bind(
            target,
            content=proxy_content,
            probe=self.proxy_probe,
            probe_url=str(config.get("proxy_probe_url") or "https://chatgpt.com/"),
            driver=driver,
            perform_probe=False,
            health_probe_ttl_seconds=int(config["proxy_health_probe_ttl_seconds"]) if "proxy_health_probe_ttl_seconds" in config else 0,
        )
        camoufox_result = {"driver": driver}
        if driver == "camoufox" and not self._custom_runner:
                camoufox_result = _runtime_module().CamoufoxRunner.preflight(config)
        return {
            **runtime_info(),
            "driver": driver,
            "target_count": target,
            "mailboxes": available,
            "proxies": len(bindings),
            "protocol": protocol_result,
            "camoufox": camoufox_result,
            "proxy_selection": {"country": "", "group": ""},
        }

    def preflight_proxies(self, *, proxy_content: str = "", probe_url: str = "https://chatgpt.com/", driver: str = "protocol", country: str | None = None, group: str | None = None, scheme: str | None = None, tls_verify: bool = True, tls_compat_fallback: bool = True, socks5_dns_mode: str = "declared", layered_probe: bool = False) -> dict[str, Any]:
        """Probe the isolated Free proxy pool without consuming mailboxes or tasks."""
        normalized_driver = str(driver or "protocol").strip().lower()
        if normalized_driver not in {"protocol", "camoufox"}:
            raise FreeRegisterError(
                "free_config", "Free 代理预检", "Free 注册链路只能选择全协议或 Camoufox", retryable=False,
                error_code="free_driver_unsupported",
            )
        driver = normalized_driver
        self.proxies.configure_policy(
            tls_verify=tls_verify,
            tls_compat_fallback=tls_compat_fallback,
            socks5_dns_mode=socks5_dns_mode,
        )
        if proxy_content.strip() and scheme:
            self.proxies.default_scheme = str(scheme).strip().lower()
        saved_pool = not str(proxy_content or "").strip()
        values = self.proxies.values(proxy_content)
        if not values:
            raise FreeRegisterError("free_proxy_preflight", "Free 代理预检", "请先粘贴或保存至少一个 Free 代理", retryable=False)
        try:
            target_domain = str(urlsplit(str(probe_url or "")).hostname or "").lower()
        except (TypeError, ValueError):
            target_domain = ""
        # Probe adapters may include a credential-bearing value from their
        # transport exception. Keep a request-wide denylist so a stale or
        # misattributed exception cannot expose another row's credentials.
        all_proxy_secrets: set[str] = set()
        for candidate in values:
            try:
                parsed_candidate = self.proxies._parse_lines(
                    candidate,
                    country="",
                    group="",
                    scheme=self.proxies.default_scheme,
                )
                if parsed_candidate:
                    all_proxy_secrets.update(
                        str(parsed_candidate[0].get(key) or "")
                        for key in ("username", "password")
                        if str(parsed_candidate[0].get(key) or "")
                    )
            except Exception:
                continue
        diagnostics: list[dict[str, Any]] = []
        pool_health_write_errors: list[dict[str, str]] = []

        def probe_row(index: int, value: str) -> dict[str, Any]:
            try:
                layered = None
                if layered_probe and self.proxy_probe is None:
                    layered = self.proxies.layered_probe(value, probe_url)
                    if not layered.get("ok"):
                        raise FreeRegisterError(
                            str(layered.get("failure_node") or "free_proxy_preflight"),
                            "Free 代理分层探测",
                            str(layered.get("failure_reason") or "代理分层探测失败"),
                            retryable=True,
                            provider_status=layered.get("http_status")
                            or layered.get("https_status")
                            or layered.get("chatgpt_status"),
                        )
                # A layered probe already performed the transport and
                # ChatGPT-login requests. Reusing its result avoids issuing a
                # second full HTTPS request for the same proxy during one
                # preflight, which was a major source of slow diagnostics.
                self.proxies.bind(
                    1,
                    content=value,
                    probe=self.proxy_probe,
                    probe_url=probe_url,
                    driver=driver,
                    perform_probe=layered is None,
                )
                row = dict((getattr(self.proxies, "_last_bind_diagnostics", ()) or [{}])[0])
                row.setdefault("index", index)
                row.setdefault("available", True)
                row.setdefault("http_status", 200)
                row.setdefault("failure_node", "")
                row.setdefault("failure_reason", "")
                if row.get("available"):
                    # Keep successful rows on the same public contract as
                    # failures, while never attaching a fabricated failure.
                    row.setdefault("declared_scheme", row.get("scheme") or "")
                    row.setdefault("effective_scheme", row.get("scheme") or "")
                    row.setdefault("provider_status", row.get("http_status"))
                    row.setdefault("provider_code", "")
                if layered is not None:
                    row["layered_probe"] = layered
                    row["http_status"] = (
                        layered.get("http_status")
                        or layered.get("https_status")
                        or layered.get("chatgpt_status")
                    )
                    row["proxy_to_target_ms"] = layered.get("https_request_ms")
                if saved_pool:
                    # A successful manual recheck is explicit health evidence:
                    # clear quarantine and make the saved row eligible again.
                    parsed = self.proxies._parse_lines(value, country="", group="", scheme=self.proxies.default_scheme)
                    record = parsed[0] if parsed else {}
                    proxy_id = str(record.get("proxy_id") or "")
                    if proxy_id:
                        try:
                            self.proxies.record_success(
                                proxy_id,
                                latency_ms=row.get("proxy_to_target_ms"),
                                probe_mode=str(row.get("probe_mode") or "manual"),
                                effective_scheme=str(row.get("effective_scheme") or ""),
                                http_status=row.get("http_status"),
                            )
                        except Exception as health_exc:
                            # A successful transport probe remains successful
                            # even when the optional health snapshot cannot be
                            # persisted. Keep the row available and continue
                            # probing the rest of the pool; surface the write
                            # problem in the aggregate diagnostics instead of
                            # misclassifying a healthy proxy as unavailable.
                            pool_health_write_errors.append({
                                "proxy_id": proxy_id,
                                "error_type": type(health_exc).__name__,
                            })
                            self._log(
                                "[Free 代理预检/free_proxy_health] 代理健康状态保存失败，保留成功探测结果",
                                "warn",
                                node_code="free_proxy_health",
                                node_label="记录 Free 代理成功",
                                outcome="cleanup_failed",
                                failure={
                                    "error_code": "free_proxy_health_write_failed",
                                    "technical_summary": f"代理健康状态保存失败（{type(health_exc).__name__}）",
                                    "retryable": True,
                                    "action_hint": "检查 Free 代理池存储状态；本次探测结果仍有效。",
                                },
                                workflow="cleanup",
                            )
            except Exception as exc:
                failure = exception_to_failure(
                    exc,
                    node_code=str(
                        getattr(exc, "node_code", "")
                        or getattr(exc, "error_code", "")
                        or "proxy_connect_failed"
                    ),
                    node_label=str(getattr(exc, "node_label", "") or "代理连接失败"),
                )
                parsed = self.proxies._parse_lines(value, country="", group="", scheme=self.proxies.default_scheme)
                record = parsed[0] if parsed else {}
                proxy_secrets = sorted(all_proxy_secrets, key=len, reverse=True)
                for key in ("public_message", "technical_summary", "action_hint", "diagnostic"):
                    detail = str(failure.get(key) or "")
                    for secret in proxy_secrets:
                        detail = detail.replace(secret, "********")
                    if detail:
                        failure[key] = sanitize_failure_text(detail, 800 if key != "action_hint" else 300)
                declared_scheme = str(record.get("scheme") or self.proxies.default_scheme)
                transport_proxy = proxy_transport_value(
                    value,
                    driver=driver,
                    socks5_dns_mode=socks5_dns_mode,
                )
                try:
                    effective_scheme = str(urlsplit(transport_proxy).scheme or declared_scheme).lower()
                except (TypeError, ValueError):
                    effective_scheme = declared_scheme
                enriched_failure = canonical_failure({
                    **failure,
                    "declared_scheme": declared_scheme,
                    "transport_scheme": effective_scheme,
                    "target_domain": target_domain,
                    "request_stage": "manual_proxy_preflight",
                    "retry_count": 0,
                    "transport_error_code": (
                        failure.get("transport_error_code")
                        if str(failure.get("transport_error_code") or "") in {
                            "proxy_protocol_mismatch", "proxy_auth_rejected", "proxy_dns_failed",
                            "proxy_connect_timeout", "proxy_connection_reset",
                            "proxy_tls_certificate_error", "proxy_connect_failed", "tls_connection_failed",
                        }
                        else ""
                    ),
                }) or failure
                row = {
                    "index": index,
                    "masked": _mask_proxy(value),
                    "fingerprint": str(record.get("proxy_id") or ""),
                    "scheme": declared_scheme,
                    "declared_scheme": declared_scheme,
                    "effective_scheme": effective_scheme,
                    "available": False,
                    "http_status": enriched_failure.get("http_status"),
                    "provider_status": enriched_failure.get("http_status"),
                    "provider_code": enriched_failure.get("provider_code") or "",
                    "local_to_proxy_ms": None,
                    "proxy_to_target_ms": None,
                    "failure_node": enriched_failure.get("node_code") or "proxy_connect_failed",
                    "failure_reason": enriched_failure.get("technical_summary") or enriched_failure.get("public_message") or "代理请求失败",
                    "failure": enriched_failure,
                }
                if saved_pool and is_proxy_health_failure(exc):
                    proxy_id = str(record.get("proxy_id") or "")
                    if proxy_id:
                        try:
                            self.proxies.record_failure(
                                proxy_id,
                                node_code=str(enriched_failure.get("node_code") or "proxy_connect_failed"),
                                message=str(enriched_failure.get("technical_summary") or enriched_failure.get("public_message") or "代理请求失败"),
                                http_status=enriched_failure.get("http_status"),
                            )
                        except Exception as health_exc:
                            # Pool health bookkeeping is advisory. A storage
                            # outage must not abort the remaining proxy probes
                            # or prevent their failures from being aggregated
                            # into the single taskless preflight incident.
                            pool_health_write_errors.append({
                                "proxy_id": proxy_id,
                                "error_type": type(health_exc).__name__,
                            })
                            self._log(
                                "[Free 代理预检/free_proxy_health] 代理健康状态保存失败，继续检测其余代理",
                                "warn",
                                node_code="free_proxy_health",
                                node_label="记录 Free 代理失败",
                                outcome="cleanup_failed",
                                failure={
                                    "error_code": "free_proxy_health_write_failed",
                                    "technical_summary": f"代理健康状态保存失败（{type(health_exc).__name__}）",
                                    "retryable": True,
                                    "action_hint": "检查 Free 代理池存储状态；本次预检结果仍会汇总返回。",
                                },
                                workflow="cleanup",
                            )
            row["index"] = index
            return row

        # Probes are independent per-row TLS round trips; running them
        # concurrently keeps large-pool manual checks from scaling linearly
        # with the saved proxy count. Results are re-ordered by index so the
        # public row contract stays stable.
        rows_by_index: dict[int, dict[str, Any]] = {}
        if len(values) == 1:
            rows_by_index[1] = probe_row(1, values[0])
        else:
            probe_workers = min(8, max(2, len(values)))
            with ThreadPoolExecutor(max_workers=probe_workers, thread_name_prefix="free-proxy-preflight") as probe_pool:
                pending = {
                    probe_pool.submit(probe_row, index, value): index
                    for index, value in enumerate(values, 1)
                }
                for future in as_completed(pending):
                    rows_by_index[pending[future]] = future.result()
        diagnostics = [rows_by_index[index] for index in sorted(rows_by_index)]
        result: dict[str, Any] = {
            **runtime_info(),
            "proxies": len([row for row in diagnostics if row.get("available")]),
            "rows": diagnostics,
        }
        if pool_health_write_errors:
            result["health_write_failures"] = len(pool_health_write_errors)
        failed_rows = [row for row in diagnostics if not row.get("available")]
        if not failed_rows:
            return result

        failures = [
            row.get("failure")
            for row in failed_rows
            if isinstance(row.get("failure"), Mapping)
        ]
        first_failure = failures[0] if failures else {}
        nodes = sorted({str(row.get("failure_node") or "") for row in failed_rows if row.get("failure_node")})
        http_statuses = sorted({
            int(row["http_status"])
            for row in failed_rows
            if isinstance(row.get("http_status"), int)
        })
        provider_codes = sorted({str(row.get("provider_code") or "") for row in failed_rows if row.get("provider_code")})
        declared_schemes = sorted({
            str(row.get("declared_scheme") or row.get("scheme") or "")
            for row in failed_rows
            if row.get("declared_scheme") or row.get("scheme")
        })
        effective_schemes = sorted({str(row.get("effective_scheme") or "") for row in failed_rows if row.get("effective_scheme")})
        proxy_fingerprints = [str(row.get("fingerprint") or "") for row in failed_rows if row.get("fingerprint")]
        failure_count = len(failed_rows)
        total_count = len(diagnostics)
        aggregate_node = str(first_failure.get("node_code") or (nodes[0] if nodes else "free_proxy_preflight"))
        aggregate_failure = canonical_failure({
            "node_code": aggregate_node,
            "node_label": first_failure.get("node_label") or "Free 代理预检",
            "error_code": first_failure.get("error_code") or "free_proxy_preflight_failed",
            "provider_code": provider_codes[0] if len(provider_codes) == 1 else "",
            "public_message": f"Free 代理连通性检测完成：共 {total_count} 条，失败 {failure_count} 条",
            "technical_summary": (
                f"代理预检失败 {failure_count}/{total_count}；"
                f"节点={','.join(nodes) or 'free_proxy_preflight'}；"
                f"HTTP={','.join(str(value) for value in http_statuses) or '-'}"
                + (f"；代理健康状态写入失败={len(pool_health_write_errors)}" if pool_health_write_errors else "")
            ),
            "retryable": bool(failures) and all(bool(item.get("retryable")) for item in failures),
            "http_status": http_statuses[0] if len(http_statuses) == 1 else None,
            "action_hint": first_failure.get("action_hint") or "按失败节点检查代理协议、认证、DNS 和目标站点响应后重试。",
            "declared_scheme": declared_schemes[0] if len(declared_schemes) == 1 else "",
            "transport_scheme": effective_schemes[0] if len(effective_schemes) == 1 else "",
            "target_domain": target_domain,
            "request_stage": "manual_proxy_preflight",
            "retry_count": 0,
            "transport_error_code": first_failure.get("transport_error_code") or "",
        }, default_node_code="free_proxy_preflight", default_node_label="Free 代理预检")
        if aggregate_failure is None:  # pragma: no cover - identity is populated above
            return result
        result.update({"failure_count": failure_count, "failure": aggregate_failure})

        log_store = getattr(self, "log_store", None)
        diagnostic_store = getattr(log_store, "diagnostic_store", None)
        incident_id = ""
        if diagnostic_store is not None:
            try:
                writer = getattr(log_store, "diagnostic_writer", None)
                if writer is None:
                    writer = DiagnosticEventWriter(
                        diagnostic_store,
                        context=LogContext(
                            chain="free",
                            workflow="proxy_preflight",
                            driver=str(driver or "protocol"),
                        ),
                    )
                incident_id = writer.record({
                    "level": "error",
                    "outcome": "error",
                    "chain": "free",
                    "workflow": "proxy_preflight",
                    "driver": str(driver or "protocol"),
                    "node_code": aggregate_failure.get("node_code"),
                    "node_label": aggregate_failure.get("node_label"),
                    "message": aggregate_failure.get("public_message"),
                    "failure": aggregate_failure,
                    "transport": {
                        "failure_count": failure_count,
                        "total_count": total_count,
                        "target_domain": target_domain,
                        "nodes": ",".join(nodes),
                        "http_statuses": ",".join(str(value) for value in http_statuses),
                        "provider_statuses": ",".join(str(row.get("provider_status")) for row in failed_rows if row.get("provider_status") is not None),
                        "provider_codes": ",".join(provider_codes),
                        "declared_schemes": ",".join(declared_schemes),
                        "effective_schemes": ",".join(effective_schemes),
                        "proxy_fingerprints": ",".join(proxy_fingerprints),
                        "health_write_failures": len(pool_health_write_errors),
                    },
                })
            except Exception:
                incident_id = ""
        # Preflight is a one-shot admin action whose API response embeds the
        # incident id and whose UI reads diagnostics right away; drain the
        # async queue so the incident is durable before returning.
        flush = getattr(writer, "flush", None)
        if incident_id and callable(flush):
            try:
                flush(2.0)
            except Exception:
                # A late drain only delays visibility; never fail preflight.
                pass
        if incident_id:
            result["incident_id"] = incident_id
            for row in failed_rows:
                row["incident_id"] = incident_id
        return result


__all__ = [
    "FreeRegisterPreflightMixin",
]
