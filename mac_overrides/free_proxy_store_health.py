"""Health probe and success/failure bookkeeping mixin for the Free proxy pool.

Split out of ``free_proxy_store.py``; the original module re-exports the
private probe helpers so legacy imports keep working.  The host class must
provide ``_load``/``_save``/``_lock`` plus the policy attributes consumed
below (``proxy_tls_verify``, ``proxy_tls_compat_fallback``,
``socks5_dns_mode``, ``failure_threshold``, ``quarantine_seconds``).
"""

from __future__ import annotations

import socket
import threading
import time
from typing import Any
from urllib.parse import urlsplit

try:
    from .free_proxy_chatgpt import probe_chatgpt_login, _without_proxy_environment
    from .free_proxy_http import get_via_proxy
    from .free_proxy_numeric import safe_float as _safe_float, safe_int as _safe_int
    from .free_proxy_parse import (
        DEFAULT_PROXY_PROBE_URL,
        normalize_probe_url,
        _extract_probe_ip,
        _is_chatgpt_probe_target,
        _is_tls_compatibility_error,
    )
    from .free_register_common import (
        FreeRegisterError,
        proxy_error_code,
        proxy_error_detail,
        safe_log_message,
        proxy_transport_value,
    )
    from .free_protocol_bootstrap import _security_challenge_html
except ImportError:  # macOS launcher imports overrides as top-level modules.
    from free_proxy_chatgpt import probe_chatgpt_login, _without_proxy_environment  # type: ignore[no-redef]
    from free_proxy_http import get_via_proxy  # type: ignore[no-redef]
    from free_proxy_numeric import safe_float as _safe_float, safe_int as _safe_int  # type: ignore[no-redef]
    from free_proxy_parse import (  # type: ignore[no-redef]
        DEFAULT_PROXY_PROBE_URL,
        normalize_probe_url,
        _extract_probe_ip,
        _is_chatgpt_probe_target,
        _is_tls_compatibility_error,
    )
    from free_register_common import (  # type: ignore[no-redef]
        FreeRegisterError,
        proxy_error_code,
        proxy_error_detail,
        safe_log_message,
        proxy_transport_value,
    )
    from free_protocol_bootstrap import _security_challenge_html  # type: ignore[no-redef]


CHATGPT_LOGIN_PROBE_URL = "https://chatgpt.com/login"
# A login/edge endpoint can legitimately reject an anonymous request after
# the proxy, DNS and TLS path have already succeeded.  These statuses are
# transport evidence for the default ChatGPT target, not proxy failures.
_CHATGPT_CONNECTIVITY_STATUSES = frozenset({401, 403})
# Single switch for every proxy-probe TLS toggle.  Probes always hit fixed,
# non-secret targets (chatgpt.com / ip echo endpoints) and their responses are
# validated by shape/fingerprint checks, so interception alone cannot inject
# usable data.  TLS verification stays off only to keep the curl_cffi
# chrome-impersonation fingerprint consistent across the whole probe path;
# enabling it would change handshake behaviour and break providers with
# broken cert chains.  Do not add new ``verify=`` literals at call sites;
# reference this constant instead.
_PROBE_TLS_VERIFY = False


class _ProxyProbeHTTPError(RuntimeError):
    """Credential-free HTTP failure carrying the upstream status internally."""

    def __init__(self, status: int) -> None:
        self.provider_status = int(status)
        super().__init__(f"代理探测请求返回 HTTP {self.provider_status}")


# ``_probe`` is intentionally a static compatibility method.  A thread-local
# side channel lets bind/preflight diagnostics retain the actual response code
# without changing its long-standing ``str`` return value or sharing status
# between concurrent workers.
_PROBE_CONTEXT = threading.local()


def _set_probe_status(status: int | None) -> None:
    if status is None:
        try:
            delattr(_PROBE_CONTEXT, "http_status")
        except AttributeError:
            pass
        return
    _PROBE_CONTEXT.http_status = int(status)


def _probe_status() -> int | None:
    value = getattr(_PROBE_CONTEXT, "http_status", None)
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


class FreeProxyStoreHealthMixin:
    """Probe policy and health bookkeeping shared by every storage backend."""

    @staticmethod
    def _probe(
        proxy: str,
        target: str,
        *,
        verify: bool = True,
        socks5_dns_mode: str = "declared",
    ) -> str:
        _set_probe_status(None)
        target = normalize_probe_url(target)
        # Manual diagnostics honor the pool's configured DNS policy while
        # retaining the declared scheme in storage and public metadata.
        transport_proxy = proxy_transport_value(proxy, driver="probe", socks5_dns_mode=socks5_dns_mode)
        if not transport_proxy:
            raise ValueError("代理格式无效")
        with _without_proxy_environment():
            response = get_via_proxy(
                target,
                proxy=transport_proxy,
                headers={"Accept": "text/plain, application/json", "Cache-Control": "no-cache"},
                timeout=12,
                verify=verify,
                impersonate="chrome",
                allow_redirects=True,
        )
        status = int(getattr(response, "status_code", 0) or 0)
        _set_probe_status(status if 100 <= status <= 599 else None)
        # ChatGPT may answer an anonymous request with 200, 401 or 403 while
        # serving a Cloudflare/Turnstile document.  The document wins over
        # the status code: a challenge is a hard diagnostic stop, never a
        # healthy proxy observation and never an automatic bypass signal.
        if _is_chatgpt_probe_target(target) and _security_challenge_html(response):
            raise FreeRegisterError(
                "free_proxy_preflight",
                "Free 代理预检",
                "ChatGPT 代理预检返回安全挑战页面",
                retryable=False,
                provider_status=status if 100 <= status <= 599 else None,
                error_code="free_proxy_chatgpt_security_challenge",
                action_hint="当前代理触发 Cloudflare 安全挑战，请更换代理或人工确认后重试；系统不会自动绕过",
                page_type="security_challenge",
                safe_page=target,
            )
        if not 100 <= status <= 599:
            raise ValueError("代理探测未返回有效 HTTP 状态")
        if not 200 <= status < 300 and not (
            _is_chatgpt_probe_target(target)
            and status in _CHATGPT_CONNECTIVITY_STATUSES
        ):
            # Preserve the status on the internal exception so callers can
            # distinguish an upstream 5xx (proxy-health evidence) from a
            # business 4xx/429 without parsing free-form text.
            raise _ProxyProbeHTTPError(status)
        # A connectivity probe is about the proxy request and HTTP response;
        # it must not require an IP-shaped response body.  Keep returning an
        # observed IP when a legacy ipify/ipinfo endpoint provides one so old
        # callers remain compatible, otherwise return an empty observation.
        # For ChatGPT 401/403 the body is deliberately ignored: the status is
        # an upstream authorization decision, not evidence of a broken proxy.
        try:
            return _extract_probe_ip(getattr(response, "content", b"") or b"")
        except (TypeError, ValueError):
            return ""

    def _probe_with_policy(self, proxy: str, target: str) -> tuple[str, str]:
        """Probe securely first and retry only TLS/CONNECT compatibility failures."""
        if not self.proxy_tls_verify:
            return self._probe(proxy, target, verify=_PROBE_TLS_VERIFY, socks5_dns_mode=self.socks5_dns_mode), "compat"
        try:
            return self._probe(proxy, target, verify=True, socks5_dns_mode=self.socks5_dns_mode), "strict"
        except Exception as first_error:
            if not self.proxy_tls_compat_fallback or not _is_tls_compatibility_error(first_error):
                raise
            # Keep the exact proxy, protocol and target. This is not a node or
            # protocol fallback; it only supports providers with broken certs.
            try:
                return self._probe(proxy, target, verify=_PROBE_TLS_VERIFY, socks5_dns_mode=self.socks5_dns_mode), "compat"
            except Exception as second_error:
                # Preserve both attempts for the structured diagnostic while
                # keeping the original exception type and redaction rules.
                raise second_error from first_error

    @staticmethod
    def _chatgpt_login_probe(
        proxy: str,
        *,
        verify: bool = True,
        socks5_dns_mode: str = "declared",
    ) -> int:
        return probe_chatgpt_login(
            proxy,
            verify=verify,
            socks5_dns_mode=socks5_dns_mode,
        )

    def _chatgpt_login_with_policy(self, proxy: str) -> tuple[int, str]:
        """Apply the same strict/compat TLS policy to the ChatGPT eligibility check."""
        if not self.proxy_tls_verify:
            return self._chatgpt_login_probe(
                proxy,
                verify=_PROBE_TLS_VERIFY,
                socks5_dns_mode=self.socks5_dns_mode,
            ), "compat"
        try:
            return self._chatgpt_login_probe(
                proxy,
                verify=True,
                socks5_dns_mode=self.socks5_dns_mode,
            ), "strict"
        except Exception as first_error:
            if not self.proxy_tls_compat_fallback or not _is_tls_compatibility_error(first_error):
                raise
            try:
                return self._chatgpt_login_probe(
                    proxy,
                    verify=_PROBE_TLS_VERIFY,
                    socks5_dns_mode=self.socks5_dns_mode,
                ), "compat"
            except Exception as second_error:
                raise second_error from first_error

    def layered_probe(self, proxy: str, target: str = DEFAULT_PROXY_PROBE_URL) -> dict[str, Any]:
        """Collect bounded transport timings for a diagnostic-only probe.

        This method never returns response bodies or credentials.  It is kept
        separate from normal binding so registration retains its existing
        AutoRegister probe order and cost.
        """
        configured = str(proxy or "").strip()
        parsed = urlsplit(configured)
        if not parsed.hostname or not parsed.port:
            raise ValueError("代理格式无效")
        result: dict[str, Any] = {
            "declared_scheme": parsed.scheme.lower(),
            "effective_scheme": proxy_transport_value(configured, driver="probe", socks5_dns_mode=self.socks5_dns_mode).split(":", 1)[0].lower(),
            "tcp_connect_ms": None,
            "https_request_ms": None,
            "https_status": None,
            "http_status": None,
            "chatgpt_request_ms": None,
            "chatgpt_status": None,
            "ok": False,
        }
        started = time.monotonic()
        try:
            with socket.create_connection((str(parsed.hostname), int(parsed.port)), timeout=5):
                pass
            result["tcp_connect_ms"] = int((time.monotonic() - started) * 1000)
        except Exception as exc:
            result["failure_node"] = "proxy_tcp_connect"
            result["failure_reason"] = type(exc).__name__
            return result
        started = time.monotonic()
        try:
            self._probe_with_policy(configured, target)
            result["https_status"] = _probe_status()
            result["http_status"] = result["https_status"]
            result["https_request_ms"] = int((time.monotonic() - started) * 1000)
        except Exception as exc:
            result["https_status"] = _probe_status()
            result["http_status"] = result["https_status"]
            result["https_request_ms"] = int((time.monotonic() - started) * 1000)
            result["failure_node"] = proxy_error_code(exc)
            result["failure_reason"] = proxy_error_detail(exc)
            return result
        started = time.monotonic()
        try:
            status, _mode = self._chatgpt_login_with_policy(configured)
            result["chatgpt_status"] = int(status)
            result["chatgpt_request_ms"] = int((time.monotonic() - started) * 1000)
        except Exception as exc:
            result["chatgpt_request_ms"] = int((time.monotonic() - started) * 1000)
            result["failure_node"] = getattr(exc, "error_code", "free_proxy_chatgpt_probe")
            result["failure_reason"] = proxy_error_detail(exc)
            return result
        result["ok"] = True
        return result

    def record_success(
        self,
        proxy_id: str,
        *,
        exit_ip: str = "",
        latency_ms: int | None = None,
        probe_mode: str = "",
        chatgpt_login_status: int = 0,
        chatgpt_login_probe_mode: str = "",
        effective_scheme: str = "",
        http_status: int | None = None,
    ) -> None:
        with self._lock:
            rows = self._load()
            for row in rows:
                if str(row.get("proxy_id")) != str(proxy_id):
                    continue
                now = time.time()
                latency_samples = list(row.get("probe_latencies_ms") or [])
                if latency_ms is not None:
                    latency_samples.append(max(0, int(latency_ms)))
                row.update({
                    "status": "available", "consecutive_failures": 0, "last_checked_at": now,
                    "last_exit_ip": exit_ip or row.get("last_exit_ip", ""),
                    "latency_ms": latency_ms if latency_ms is not None else row.get("latency_ms"),
                    "last_failure": None,
                    "last_probe_ok": True,
                    "probe_attempts": int(row.get("probe_attempts") or 0) + 1,
                    "probe_successes": int(row.get("probe_successes") or 0) + 1,
                    "probe_latencies_ms": latency_samples[-50:],
                })
                if chatgpt_login_status:
                    row["last_chatgpt_login_checked_at"] = now
                    row["last_chatgpt_login_status"] = int(chatgpt_login_status)
                if chatgpt_login_probe_mode:
                    row["last_chatgpt_login_probe_mode"] = str(chatgpt_login_probe_mode)
                if probe_mode:
                    row["last_probe_mode"] = str(probe_mode)
                if effective_scheme:
                    row["effective_scheme"] = str(effective_scheme).lower()
                normalized_status = _safe_int(
                    http_status,
                    default=None,
                    minimum=100,
                    maximum=599,
                )
                if normalized_status is not None:
                    row["last_probe_http_status"] = normalized_status
                row["quarantined_until"] = None
                self._save(rows)
                return

    def record_failure(
        self,
        proxy_id: str,
        *,
        node_code: str,
        message: str,
        threshold: int | None = None,
        quarantine_seconds: int | None = None,
        http_status: int | None = None,
    ) -> None:
        with self._lock:
            rows = self._load()
            for row in rows:
                if str(row.get("proxy_id")) != str(proxy_id):
                    continue
                failures = int(row.get("consecutive_failures") or 0) + 1
                limit = max(1, int(threshold or self.failure_threshold))
                row.update({"consecutive_failures": failures, "last_checked_at": time.time(), "probe_attempts": int(row.get("probe_attempts") or 0) + 1, "last_probe_ok": False, "last_failure": {"node_code": node_code, "message": safe_log_message(message)[:300]}})
                normalized_status = _safe_int(
                    http_status,
                    default=None,
                    minimum=100,
                    maximum=599,
                )
                if normalized_status is not None:
                    row["last_probe_http_status"] = normalized_status
                if failures >= limit:
                    row["status"] = "quarantined"
                    row["quarantined_until"] = time.time() + max(1, int(quarantine_seconds or self.quarantine_seconds))
                self._save(rows)
                return


__all__ = [
    "CHATGPT_LOGIN_PROBE_URL",
    "FreeProxyStoreHealthMixin",
]
