"""HTTP proxy request compatibility helpers for the isolated Free runtime."""

from __future__ import annotations

from typing import Any, Mapping


def is_curl_native_tls_compatibility_error(error: BaseException) -> bool:
    """Recognize the macOS curl_cffi/OpenSSL failure fixed by requests+PySocks.

    curl_cffi can fail before it sends a SOCKS5 request when its bundled TLS
    library is incompatible with the host LibreSSL runtime.  This is distinct
    from a proxy protocol/authentication error, so only the stable native
    error marker is eligible for the fallback.
    """
    text = str(error or "").casefold()
    return "invalid library" in text and ("curl:" in text or "tls" in text or "ssl" in text)


def get_via_proxy(
    url: str,
    *,
    proxy: str,
    headers: Mapping[str, str] | None = None,
    timeout: Any = 12,
    verify: bool = True,
    impersonate: str = "chrome",
    allow_redirects: bool = True,
) -> Any:
    """Perform one GET, falling back only for the known native TLS mismatch."""
    from curl_cffi import requests as curl_requests

    curl_session: Any = None
    try:
        curl_session = curl_requests.Session(
            impersonate=impersonate,
            verify=bool(verify),
        )
        curl_session.proxies = {"http": proxy, "https": proxy}
        if hasattr(curl_session, "trust_env"):
            curl_session.trust_env = False
        try:
            return curl_session.get(
                url,
                headers=dict(headers or {}),
                timeout=timeout,
                allow_redirects=allow_redirects,
            )
        except Exception as first_error:
            if not is_curl_native_tls_compatibility_error(first_error):
                raise
            # requests uses the system OpenSSL/PySocks path and supports the
            # same declared SOCKS5/SOCKS5H proxy URL without changing routing.
            import requests

            fallback_session = requests.Session()
            try:
                fallback_session.trust_env = False
                fallback_session.proxies = {"http": proxy, "https": proxy}
                return fallback_session.get(
                    url,
                    headers=dict(headers or {}),
                    timeout=timeout,
                    verify=bool(verify),
                    allow_redirects=allow_redirects,
                )
            except Exception as second_error:
                raise second_error from first_error
            finally:
                close_fallback = getattr(fallback_session, "close", None)
                if callable(close_fallback):
                    close_fallback()
    finally:
        close_curl = getattr(curl_session, "close", None)
        if callable(close_curl):
            close_curl()


__all__ = ["get_via_proxy", "is_curl_native_tls_compatibility_error"]
