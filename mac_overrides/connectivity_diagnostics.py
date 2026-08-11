"""On-demand, credential-free diagnostics for the OpenAI auth route."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import time
from typing import Any, Callable, Mapping, Sequence

try:
    from .auth_connectivity_runtime import AUTH_ORIGIN, SENTINEL_ORIGIN
    from .error_observability import sanitize_failure_detail
    from .mailbox_redaction import url_credential_secrets
except ImportError:  # Loaded as a top-level runtime override.
    from auth_connectivity_runtime import AUTH_ORIGIN, SENTINEL_ORIGIN  # type: ignore[no-redef]
    from error_observability import sanitize_failure_detail  # type: ignore[no-redef]
    from mailbox_redaction import url_credential_secrets  # type: ignore[no-redef]


_ORIGINS = (AUTH_ORIGIN, SENTINEL_ORIGIN)
_DEFAULT_TIMEOUT = 5.0
_MAX_NODE_TIMEOUT = 45


def _status_code(value: Any) -> int | None:
    for key in ("status_code", "http_status", "status"):
        try:
            status = int(value.get(key)) if isinstance(value, Mapping) else int(getattr(value, key, 0))
        except (TypeError, ValueError, AttributeError):
            continue
        if 100 <= status <= 599:
            return status
    return None


def _failure_reason(error: Any) -> tuple[str, str]:
    text = str(error or "").lower()
    rules = (
        (("proxyerror", "proxy connect", "unable to connect to proxy", "proxy connection"), "proxy_connection_failed", "代理连接失败"),
        (("name resolution", "could not resolve", "nodename nor servname", "getaddrinfo"), "dns_resolution_failed", "DNS 解析失败"),
        (("certificate verify", "sslerror", "ssleoferror", "tls", "handshake"), "tls_connection_failed", "TLS 握手失败"),
        (("read timed out", "readtimeout", "timed out reading"), "read_timeout", "读取响应超时"),
        (("connect timeout", "connecttimeout", "connection timed out", "operation timed out"), "connect_timeout", "连接超时"),
        (("connection refused", "network is unreachable", "no route to host"), "connection_failed", "连接建立失败"),
        (("connection reset", "remote disconnected", "connection aborted", "unexpected eof"), "remote_disconnected", "远端连接中断"),
    )
    for markers, code, label in rules:
        if any(marker in text for marker in markers):
            return code, label
    return "probe_transport_error", "网络传输失败"


def _service_status(status: int | None) -> str:
    if status is None:
        return "transport_error"
    if status == 429:
        return "rate_limited"
    if status >= 500:
        return "upstream_error"
    return "available"


def _probe_origin(
    origin: str,
    proxy: str,
    *,
    timeout: float,
    session_factory: Callable[[], Any] | None = None,
    secrets: Sequence[Any] = (),
) -> dict[str, Any]:
    started = time.monotonic()
    session = None
    try:
        if session_factory is None:
            from curl_cffi import requests

            session_factory = lambda: requests.Session(impersonate="chrome")
        session = session_factory()
        if hasattr(session, "trust_env"):
            session.trust_env = False
        cookies = getattr(session, "cookies", None)
        clear = getattr(cookies, "clear", None)
        if callable(clear):
            clear()
        kwargs: dict[str, Any] = {
            "headers": {"Accept": "*/*"},
            "timeout": timeout,
            "allow_redirects": False,
        }
        if proxy:
            kwargs["proxies"] = {"http": proxy, "https": proxy}
        response = session.get(f"https://{origin}/", **kwargs)
        status = _status_code(response)
        service_status = _service_status(status)
        labels = {
            "available": ("", "可达"),
            "rate_limited": ("http_429", "OpenAI 服务限流"),
            "upstream_error": ("http_5xx", "OpenAI 上游服务异常"),
            "transport_error": ("invalid_http_response", "未收到有效 HTTP 状态"),
        }
        reason_code, reason_label = labels[service_status]
        return {
            "origin": origin,
            "reachable": status is not None,
            "service_status": service_status,
            "service_available": service_status == "available",
            "latency_ms": round(max(0.0, time.monotonic() - started) * 1000),
            "status_code": status,
            "reason_code": reason_code,
            "reason_label": reason_label,
        }
    except Exception as exc:
        reason_code, reason_label = _failure_reason(exc)
        return {
            "origin": origin,
            "reachable": False,
            "service_status": "transport_error",
            "service_available": False,
            "latency_ms": round(max(0.0, time.monotonic() - started) * 1000),
            "status_code": None,
            "reason_code": reason_code,
            "reason_label": reason_label,
            "technical_summary": sanitize_failure_detail(exc, secrets=secrets, limit=300),
        }
    finally:
        close = getattr(session, "close", None)
        if callable(close):
            try:
                close()
            except Exception:
                pass


class OpenAIConnectivityDiagnostics:
    """Run an isolated two-stage probe without mutating the connectivity guard."""

    def __init__(
        self,
        *,
        config_getter: Callable[[], Mapping[str, Any]],
        node_bridge: Callable[..., Mapping[str, Any]],
        session_factory: Callable[[], Any] | None = None,
        now_fn: Callable[[], float] = time.time,
    ) -> None:
        self.config_getter = config_getter
        self.node_bridge = node_bridge
        self.session_factory = session_factory
        self.now_fn = now_fn

    def run(self) -> dict[str, Any]:
        config = self.config_getter()
        config = config if isinstance(config, Mapping) else {}
        proxy = str(config.get("proxy") or "").strip()
        secrets = url_credential_secrets(proxy)
        started = time.monotonic()
        with ThreadPoolExecutor(max_workers=2, thread_name_prefix="openai-diagnostic") as pool:
            futures = {
                origin: pool.submit(
                    _probe_origin,
                    origin,
                    proxy,
                    timeout=_DEFAULT_TIMEOUT,
                    session_factory=self.session_factory,
                    secrets=secrets,
                )
                for origin in _ORIGINS
            }
            network = [futures[origin].result() for origin in _ORIGINS]

        sentinel: dict[str, Any]
        sentinel_origin = next(row for row in network if row["origin"] == SENTINEL_ORIGIN)
        if not sentinel_origin["reachable"]:
            sentinel = {
                "attempted": False,
                "ok": False,
                "skipped_reason": "sentinel_origin_unreachable",
                "public_message": "Sentinel 深测已跳过：sentinel.openai.com 不可达",
            }
        elif not sentinel_origin["service_available"]:
            status_label = "正在限流" if sentinel_origin["service_status"] == "rate_limited" else "服务异常"
            sentinel = {
                "attempted": False,
                "ok": False,
                "skipped_reason": f"sentinel_origin_{sentinel_origin['service_status']}",
                "public_message": f"Sentinel 深测已跳过：sentinel.openai.com {status_label}（HTTP {sentinel_origin['status_code']}）",
            }
        else:
            node_started = time.monotonic()
            try:
                raw_timeout = int(config.get("node_timeout") or 45)
            except (TypeError, ValueError):
                raw_timeout = 45
            timeout = max(5, min(_MAX_NODE_TIMEOUT, raw_timeout))
            try:
                result = self.node_bridge(
                    mode="real",
                    device_id=str(config.get("openai_device_id") or ""),
                    proxy_label="configured-proxy" if proxy else "direct",
                    proxy=proxy,
                    fingerprint=config.get("browser_fingerprint") or config.get("openai_persona") or {},
                    flow="chat-requirements",
                    persona="chatgpt-noauth",
                    script_path=str(config.get("codex_node_runner") or ""),
                    context={"diagnostic": True},
                    timeout=timeout,
                )
                result = result if isinstance(result, Mapping) else {}
                token_ok = bool(result.get("ok") and result.get("token_generated"))
                detail = sanitize_failure_detail(result.get("error"), secrets=secrets, limit=300)
                sentinel = {
                    "attempted": True,
                    "ok": token_ok,
                    "latency_ms": round(max(0.0, time.monotonic() - node_started) * 1000),
                    "error_code": "" if token_ok else "node_sentinel_diagnostic_failed",
                    "public_message": "Sentinel token 生成成功" if token_ok else f"Sentinel token 生成失败：{detail or '服务端未返回错误详情'}",
                    "technical_summary": detail,
                }
            except Exception as exc:
                detail = sanitize_failure_detail(exc, secrets=secrets, limit=300)
                sentinel = {
                    "attempted": True,
                    "ok": False,
                    "latency_ms": round(max(0.0, time.monotonic() - node_started) * 1000),
                    "error_code": "node_sentinel_diagnostic_failed",
                    "public_message": f"Sentinel token 生成失败：{detail or '服务端未返回错误详情'}",
                    "technical_summary": detail,
                }

        transport_ok = all(row["reachable"] for row in network)
        services_ok = all(row["service_available"] for row in network)
        overall = "healthy" if services_ok and sentinel["ok"] else "degraded" if transport_ok else "failed"
        return {
            "tested_at": int(self.now_fn()),
            "proxy_configured": bool(proxy),
            "overall": overall,
            "network": network,
            "sentinel": sentinel,
            "elapsed_ms": round(max(0.0, time.monotonic() - started) * 1000),
        }


__all__ = ["OpenAIConnectivityDiagnostics"]
