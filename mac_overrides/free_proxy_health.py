"""Classify failures that are safe to charge against Free proxy health."""

from __future__ import annotations

from typing import Any


_EXIT_VERIFICATION_NODES = frozenset({"free_proxy_drift", "free_roxy_ip_verify"})
_NETWORK_EVIDENCE_NODES = frozenset({
    "free_proxy_binding",
    "free_proxy_preflight",
    "free_protocol_preflight",
    "free_oauth_session",
})
_NETWORK_ERROR_TYPES = frozenset({
    "certificateverifyerror",
    "connectionerror",
    "connectionrefusederror",
    "connectionreseterror",
    "connecterror",
    "connecttimeout",
    "dnserror",
    "gaierror",
    "nameresolutionerror",
    "proxyerror",
    "readtimeout",
    "sockettimeout",
    "sslerror",
    "timeouterror",
})
_EXIT_TEXT_MARKERS = (
    "出口 ip 响应无效",
    "出口 ip 为空",
    "出口 ip 检测失败",
    "出口复核失败",
)
_NON_NETWORK_MARKERS = (
    "config",
    "format",
    "missing",
    "required",
    "unsupported",
    "配置无效",
    "格式",
    "缺少",
    "未配置",
    "不支持",
)
_NETWORK_TEXT_MARKERS = (
    "proxy connect",
    "connect tunnel",
    "failed to connect",
    "couldn't connect",
    "connection refused",
    "connection reset",
    "proxy authentication required",
    "proxy authentication failed",
    "proxy auth failed",
    "http 407",
    "curl: (5)",
    "curl: (6)",
    "curl: (7)",
    "curl: (28)",
    "curl: (35)",
    "curl: (51)",
    "curl: (56)",
    "curl: (60)",
    "curl: (77)",
    "curl: (97)",
    "could not resolve",
    "couldn't resolve",
    "name or service not known",
    "temporary failure in name resolution",
    "nodename nor servname",
    "getaddrinfo failed",
    "certificate verify",
    "cert verify",
    "ssl handshake",
    "tls handshake",
    "timed out",
    "timeout",
    "代理连接失败",
    "代理 connect 失败",
    "连接代理失败",
    "代理认证被拒绝",
    "代理认证失败",
    "代理域名解析失败",
    "证书校验失败",
    "tls/证书握手失败",
    "连接超时",
    "请求超时",
)


def _exception_chain(error: BaseException):
    current: BaseException | None = error
    seen: set[int] = set()
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        yield current
        current = current.__cause__ or current.__context__


def is_proxy_health_failure(error: BaseException) -> bool:
    """Return true only for explicit proxy transport or exit-check failures."""
    node_code = str(getattr(error, "node_code", "") or "").strip().lower()
    if node_code in _EXIT_VERIFICATION_NODES:
        return True
    if node_code not in _NETWORK_EVIDENCE_NODES:
        return False

    details: list[str] = []
    for current in _exception_chain(error):
        if type(current).__name__.lower() in _NETWORK_ERROR_TYPES:
            return True
        details.append(str(current or ""))
        for name in ("error_code", "provider_code", "diagnostic"):
            value: Any = getattr(current, name, "")
            if value:
                details.append(str(value))
    combined = " | ".join(details).lower()
    if any(marker in combined for marker in _EXIT_TEXT_MARKERS):
        return True
    if any(marker in combined for marker in _NON_NETWORK_MARKERS):
        return False
    return any(marker in combined for marker in _NETWORK_TEXT_MARKERS)


__all__ = ["is_proxy_health_failure"]
