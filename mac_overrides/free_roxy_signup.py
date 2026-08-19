"""RoxyBrowser signup-page bootstrap and safe page diagnostics."""

from __future__ import annotations

from typing import Any, Mapping
from urllib.parse import urlsplit

try:
    from .free_register_common import FreeRegisterError
except ImportError:
    from free_register_common import FreeRegisterError  # type: ignore[no-redef]


def safe_page_location(driver: Any) -> str:
    try:
        parsed = urlsplit(str(getattr(driver, "current_url", "") or ""))
        if parsed.scheme and parsed.hostname:
            host = parsed.hostname
            if ":" in host and not host.startswith("["):
                host = f"[{host}]"
            return f"{parsed.scheme}://{host}{parsed.path or '/'}"
    except Exception:
        pass
    return "页面地址未知"


def is_email_verification_page(driver: Any) -> bool:
    try:
        parsed = urlsplit(str(getattr(driver, "current_url", "") or ""))
    except Exception:
        return False
    return (
        (parsed.hostname or "").casefold() == "auth.openai.com"
        and parsed.path.rstrip("/").casefold() in {"/email-verification", "/email-otp"}
    )


def _is_trusted_auth_page(driver: Any) -> bool:
    try:
        parsed = urlsplit(str(getattr(driver, "current_url", "") or ""))
    except Exception:
        return False
    host = (parsed.hostname or "").casefold()
    path = parsed.path.casefold()
    if host == "chatgpt.com":
        return path == "/" or path.startswith("/auth/")
    return host == "auth.openai.com" and path.startswith((
        "/api/accounts/authorize", "/authorize", "/log-in", "/sign-up",
        "/email-verification", "/email-otp", "/create-account", "/about-you",
    ))


def open_signup_page(driver: Any, email: str, timeout: int) -> None:
    """Create the same-origin auth context before navigating to the signup page."""
    driver.set_page_load_timeout(timeout)
    try:
        driver.get("https://chatgpt.com/")
        result = driver.execute_async_script(
            """
            const email = arguments[0];
            const done = arguments[arguments.length - 1];
            (async () => {
              const csrfResponse = await fetch('/api/auth/csrf', {
                credentials: 'include', headers: {accept: 'application/json'},
              });
              const csrf = await csrfResponse.json().catch(() => ({}));
              const csrfToken = String(csrf.csrfToken || '');
              if (!csrfResponse.ok || !csrfToken) {
                return {ok: false, step: 'csrf', status: csrfResponse.status || 0};
              }
              const deviceCookie = document.cookie.split(';').map(v => v.trim())
                .find(v => v.startsWith('oai-did='));
              const randomId = () => crypto.randomUUID ? crypto.randomUUID() : String(Date.now());
              const deviceId = deviceCookie
                ? decodeURIComponent(deviceCookie.slice('oai-did='.length)) : randomId();
              const query = new URLSearchParams({
                prompt: 'login', 'ext-oai-did': deviceId,
                auth_session_logging_id: randomId(),
                'ext-passkey-client-capabilities': '0111',
                screen_hint: 'signup', login_hint: email,
              });
              const body = new URLSearchParams({
                callbackUrl: 'https://chatgpt.com/', csrfToken, json: 'true',
              });
              const response = await fetch('/api/auth/signin/openai?' + query.toString(), {
                method: 'POST', credentials: 'include', redirect: 'follow',
                headers: {accept: 'application/json', 'content-type': 'application/x-www-form-urlencoded'},
                body: body.toString(),
              });
              const payload = await response.json().catch(() => ({}));
              return {ok: response.ok && Boolean(payload.url), step: 'signin',
                status: response.status || 0, url: String(payload.url || '')};
            })().then(done).catch(error => done({ok: false, step: 'script', error: String(error)}));
            """,
            str(email or ""),
        ) or {}
    except Exception as exc:
        raise FreeRegisterError(
            "free_roxy_signup_bootstrap", "打开 RoxyBrowser 注册页",
            f"注册页初始化超时或导航失败（{type(exc).__name__}，{safe_page_location(driver)}）",
            error_code="free_roxy_signup_bootstrap_timeout" if type(exc).__name__ == "TimeoutException" else "free_roxy_signup_bootstrap_failed",
        ) from exc
    auth_url = str(result.get("url") or "") if isinstance(result, Mapping) else ""
    parsed = urlsplit(auth_url)
    if (
        not isinstance(result, Mapping) or not result.get("ok")
        or parsed.scheme != "https"
        or (parsed.hostname or "").casefold() not in {"auth.openai.com", "chatgpt.com"}
    ):
        step = str(result.get("step") or "unknown") if isinstance(result, Mapping) else "unknown"
        status = result.get("status") if isinstance(result, Mapping) else None
        raise FreeRegisterError(
            "free_roxy_signup_bootstrap", "打开 RoxyBrowser 注册页",
            f"注册页初始化响应无效（步骤 {step}，HTTP {status or '-'}）",
            error_code="free_roxy_signup_bootstrap_response_invalid",
        )
    try:
        driver.get(auth_url)
    except Exception as exc:
        # Roxy/Chrome may report a navigation error after the auth redirect has
        # already committed. Continue only when the visible page is a known
        # OpenAI auth location; all other navigation failures remain fatal.
        if _is_trusted_auth_page(driver):
            return
        raise FreeRegisterError(
            "free_roxy_signup_bootstrap", "打开 RoxyBrowser 注册页",
            f"注册页导航失败（{type(exc).__name__}，{safe_page_location(driver)}）",
            error_code="free_roxy_signup_navigation_timeout" if type(exc).__name__ == "TimeoutException" else "free_roxy_signup_navigation_failed",
        ) from exc


__all__ = ["is_email_verification_page", "open_signup_page", "safe_page_location"]
