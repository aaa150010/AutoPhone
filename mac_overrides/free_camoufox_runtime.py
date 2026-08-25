"""Optional Camoufox browser driver for the Free registration workflow.

Camoufox is deliberately imported lazily.  The existing protocol and
RoxyBrowser drivers remain usable when the optional browser package is absent.
The browser pool owns only browser/context lifecycle; mailbox, result and
failure semantics stay in the Free runtime and shared account service.
"""

from __future__ import annotations

import asyncio
import atexit
from concurrent.futures import TimeoutError as FutureTimeoutError
from dataclasses import dataclass
import inspect
import json
import os
import random
import threading
import time
import traceback
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit, urlencode
import uuid

try:
    from .free_account_service import (
        CHATGPT_ACCOUNTS_URL,
        CHATGPT_ELIGIBILITY_URL,
        browser_json_fetch,
        browser_session,
        browser_twofa,
        finalize_registration_result,
        plan_details_from_payloads,
    )
    from .free_register_common import (
        FIXED_PASSWORD,
        FreeRegisterError,
        clean,
        random_birthdate,
        random_display_name,
        safe_log_message,
    )
    from .free_mailbox_otp import build_free_mailbox_otp_provider
except ImportError:  # pragma: no cover - top-level recovery import
    from free_account_service import (  # type: ignore[no-redef]
        CHATGPT_ACCOUNTS_URL, CHATGPT_ELIGIBILITY_URL, browser_json_fetch,
        browser_session, browser_twofa, finalize_registration_result,
        plan_details_from_payloads,
    )
    from free_register_common import (  # type: ignore[no-redef]
        FIXED_PASSWORD, FreeRegisterError, clean, random_birthdate, random_display_name,
        safe_log_message,
    )
    from free_mailbox_otp import build_free_mailbox_otp_provider  # type: ignore[no-redef]


CHATGPT_LOGIN_URL = "https://chatgpt.com/auth/login"
EMAIL_SELECTORS = (
    "input#login-email", "input[type='email']", "input[name='email']",
    "input[name='username']", "input[autocomplete='username']",
    "input[autocomplete*='username']", "input[autocomplete*='email']",
    "input[inputmode='email']", "input[id*='email' i]",
)
OTP_SELECTORS = (
    "input[autocomplete='one-time-code']", "input[inputmode='numeric']",
    "input[type='tel']", "input[name*='code' i]", "input[id*='code' i]",
)
PASSWORD_SELECTORS = (
    "input[type='password']", "input[name='password']", "input[name*='password' i]",
    "input[autocomplete='new-password']",
)
NAME_SELECTORS = (
    "input[name='name']", "input[name='full_name']", "input[autocomplete='name']",
    "input[placeholder*='name' i]",
)
BIRTHDAY_SELECTORS = (
    "input[type='date']", "input[name*='birth' i]", "input[name*='birthday' i]",
)
AGE_SELECTORS = (
    "input[name='age']", "input[name*='age' i]", "input[placeholder*='age' i]",
)
SUBMIT_SELECTORS = (
    "button[type='submit']", "input[type='submit']", "button[data-testid='continue-button']",
    "button:has-text('Continue')", "button:has-text('continue')", "button:has-text('Next')",
    "button:has-text('Sign up')", "button:has-text('Create account')",
    "button:has-text('继续')", "button:has-text('Verify')", "button:has-text('Create')",
    "button:has-text('注册')", "button:has-text('创建账号')",
)
PASSWORDLESS_SELECTORS = (
    "a[href*='passwordless']", "button:has-text('email code')",
    "button:has-text('Email code')", "button:has-text('Use email')",
    "a:has-text('Use email')", "button:has-text('邮箱验证码')",
)
RESEND_SELECTORS = (
    "button:has-text('Resend')", "button:has-text('resend')",
    "button:has-text('重新发送')", "button:has-text('重发')",
    "a[href*='resend' i]", "[role='button']:has-text('Resend')",
)
PROFILE_SUBMIT_SELECTORS = (
    "button[type='submit']", "button[data-testid='continue-button']",
    "button:has-text('Continue')", "button:has-text('Sign up')",
    "button:has-text('Create account')", "button:has-text('完成')",
)


class CamoufoxDependencyError(FreeRegisterError):
    def __init__(self, detail: str = "") -> None:
        super().__init__(
            "free_camoufox_dependency", "检查 Camoufox 依赖",
            "Camoufox 未安装或运行时不可用" + (f"（{clean(detail, 180)}）" if detail else ""),
            retryable=False,
            error_code="camoufox_dependency_missing",
            action_hint="安装 camoufox 及其浏览器运行时后重新执行 Free 预检",
        )


class CamoufoxBrowserError(FreeRegisterError):
    pass


_BROWSER_PROCESS_LOST_MARKERS = (
    "target page, context or browser has been closed",
    "browser has been closed",
    "browser closed",
    "browser disconnected",
    "target closed",
    "connection closed while reading from the driver",
    "playwright connection closed",
)

_PROXY_BLOCK_PAGE_MARKERS = (
    "unable to load site",
    "if you are using a vpn",
    "access denied",
    "sorry, you have been blocked",
    "web proxy blocked",
    "proxy blocked",
    "代理被阻断",
    "代理阻断",
)


def _browser_process_lost(exc: BaseException) -> bool:
    message = str(exc or "").casefold()
    return any(marker in message for marker in _BROWSER_PROCESS_LOST_MARKERS)


def _load_camoufox_api() -> tuple[Any, Any]:
    try:
        from camoufox.async_api import AsyncCamoufox, AsyncNewContext
    except Exception as exc:  # pragma: no cover - environment dependent
        raise CamoufoxDependencyError(type(exc).__name__) from exc
    return AsyncCamoufox, AsyncNewContext


def _check_camoufox_runtime() -> str:
    """Require the browser binary, not only the optional Python package."""
    try:
        from camoufox.pkgman import installed_verstr
    except Exception as exc:  # pragma: no cover - package-version dependent
        raise CamoufoxDependencyError(type(exc).__name__) from exc
    try:
        version = str(installed_verstr() or "").strip()
    except Exception as exc:  # pragma: no cover - environment dependent
        raise CamoufoxDependencyError(type(exc).__name__) from exc
    if not version:
        raise CamoufoxDependencyError("browser runtime unavailable")
    return version


def _camoufox_error_detail(exc: BaseException) -> str:
    """Keep nested launch diagnostics while applying the normal redaction."""
    parts: list[str] = []
    current: BaseException | None = exc
    seen: set[int] = set()
    while current is not None and id(current) not in seen and len(parts) < 3:
        seen.add(id(current))
        error_code = str(getattr(current, "error_code", "") or "").strip()
        diagnostic = str(getattr(current, "diagnostic", "") or "").strip()
        # Exception messages can contain page text or provider payloads.  Keep
        # only structured fields and the exception class unless a dedicated
        # diagnostic was already supplied by our own error type.
        detail = ": ".join(item for item in (error_code, diagnostic) if item)
        if not detail:
            frame = ""
            try:
                frames = traceback.extract_tb(current.__traceback__)
                if frames:
                    last = frames[-1]
                    frame = f"@{os.path.basename(last.filename)}:{last.lineno}:{last.name}"
            except Exception:
                frame = ""
            detail = f"{type(current).__name__}{frame}"
        if detail:
            parts.append(detail[:240])
        current = current.__cause__ or current.__context__
    return " <- ".join(parts)[:500]


def _safe_url(page: Any) -> str:
    try:
        parsed = urlsplit(str(getattr(page, "url", "") or ""))
        if parsed.scheme and parsed.hostname:
            return f"{parsed.scheme}://{parsed.hostname}{parsed.path or '/'}"
    except Exception:
        pass
    return "页面地址未知"


async def _body_text(page: Any) -> str:
    try:
        return clean(await page.locator("body").inner_text(timeout=1500), 1800)
    except Exception:
        return ""


async def _snapshot(page: Any) -> dict[str, Any]:
    body = await _body_text(page)
    try:
        title = clean(await page.title(), 160)
    except Exception:
        title = ""
    return {"url": _safe_url(page), "title": title, "body": body}


async def _page_visible_text(page: Any) -> str:
    return await _body_text(page)


async def _hard_proxy_block_reason(page: Any) -> str:
    snapshot = await _snapshot(page)
    combined = f"{snapshot['title']} {snapshot['body']}".casefold()
    marker = next((item for item in _PROXY_BLOCK_PAGE_MARKERS if item in combined), "")
    if not marker:
        return ""
    return f"ChatGPT 拒绝当前代理（{marker}）"


async def _is_cloudflare_challenge(page: Any) -> bool:
    snapshot = await _snapshot(page)
    combined = f"{snapshot['title']} {snapshot['body']}".casefold()
    return any(marker in combined for marker in (
        "cloudflare", "just a moment", "verify you are human", "turnstile",
        "checking your browser", "performing security verification", "安全验证",
    ))


async def _wait_challenge_then_stop(page: Any, *, timeout: float = 30.0) -> None:
    """Wait briefly for a challenge to clear, then stop without bypassing it."""
    if not await _is_cloudflare_challenge(page):
        return
    deadline = time.monotonic() + max(0.0, float(timeout))
    while time.monotonic() < deadline:
        await asyncio.sleep(2.0)
        if not await _is_cloudflare_challenge(page):
            return
    raise CamoufoxBrowserError(
        "free_camoufox_challenge", "等待 Camoufox 安全验证",
        "Camoufox 页面安全验证未在等待窗口内完成",
        retryable=False, error_code="free_camoufox_security_challenge",
        safe_page=_safe_url(page), page_type="security",
    )


async def _wait_for_any_selector(page: Any, selectors: tuple[str, ...], *, timeout: float = 30.0) -> str | None:
    deadline = time.monotonic() + max(0.1, float(timeout))
    while time.monotonic() < deadline:
        for selector in selectors:
            try:
                locator = page.locator(selector).first
                if await locator.is_visible(timeout=500):
                    return selector
            except Exception:
                continue
        await asyncio.sleep(0.4)
    return None


async def _find_visible_selector(page: Any, selectors: tuple[str, ...]) -> str | None:
    for selector in selectors:
        try:
            if await page.locator(selector).first.is_visible(timeout=500):
                return selector
        except Exception:
            continue
    return None


async def _fill_input_like_user(page: Any, selector: str, value: str) -> bool:
    try:
        locator = page.locator(selector).first
        await locator.wait_for(state="visible", timeout=8000)
        await locator.click()
        await locator.fill("")
        await locator.fill(str(value))
        return True
    except Exception:
        try:
            await page.locator(selector).first.fill(str(value))
            return True
        except Exception:
            return False


async def _click_first(page: Any, selectors: tuple[str, ...], *, timeout: float = 8.0) -> str | None:
    for selector in selectors:
        try:
            locator = page.locator(selector).first
            await locator.wait_for(state="visible", timeout=max(500, int(timeout * 1000)))
            await locator.click(timeout=5000)
            return selector
        except Exception:
            continue
    return None


async def _wait_for_submit_enabled(page: Any, selectors: tuple[str, ...], *, timeout: float = 20.0) -> str | None:
    deadline = time.monotonic() + max(0.1, float(timeout))
    while time.monotonic() < deadline:
        for selector in selectors:
            try:
                locator = page.locator(selector).first
                if not await locator.is_visible(timeout=500):
                    continue
                if not await locator.get_attribute("disabled"):
                    return selector
            except Exception:
                continue
        await asyncio.sleep(0.5)
    return None


async def _submit_visible_form(page: Any, selector: str) -> bool:
    try:
        await page.locator(selector).first.press("Enter")
        return True
    except Exception:
        return False


async def _submit_email_form_stable(page: Any, email: str) -> dict[str, Any]:
    """Submit the React-controlled email form without blocking navigation."""
    script = r"""
    ({email}) => {
      const value = String(email || '').trim();
      const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
        && getComputedStyle(el).visibility !== 'hidden'
        && getComputedStyle(el).display !== 'none'
        && !el.disabled && el.getAttribute('aria-disabled') !== 'true';
      const input = [...document.querySelectorAll(
        "input#login-email,input[type='email'],input[name='email'],input[name='username'],input[autocomplete*='email'],input[autocomplete*='username']"
      )].find(el => visible(el) && !el.readOnly);
      if (!input) return {ok: false, reason: 'missing_email_input'};
      if (!value || !value.includes('@')) return {ok: false, reason: 'empty_email'};
      const form = input.closest('form');
      if (!form) return {ok: false, reason: 'missing_form'};
      const bad = /google|apple|microsoft|github|facebook|saml|sso|oauth|social|oidc|idp|provider|authorize|consent|grant|allow/i;
      const describe = el => [el.id, el.name, el.type, el.getAttribute('data-testid'),
        el.getAttribute('data-provider'), el.getAttribute('aria-label'), el.getAttribute('href'),
        el.textContent || ''].filter(Boolean).join(' ');
      const buttons = [...form.querySelectorAll('button,input[type="submit"]')]
        .filter(el => visible(el) && !bad.test(describe(el)));
      const submit = buttons.find(el => (el.getAttribute('type') || '').toLowerCase() === 'submit')
        || buttons[0] || null;
      if (!submit) return {ok: false, reason: 'missing_safe_submit'};
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
      input.scrollIntoView({block: 'center', inline: 'nearest'});
      input.focus();
      if (setter) setter.call(input, value); else input.value = value;
      try { input.dispatchEvent(new InputEvent('beforeinput', {bubbles: true, cancelable: true, inputType: 'insertText', data: value})); } catch (_) {}
      try { input.dispatchEvent(new InputEvent('input', {bubbles: true, inputType: 'insertText', data: value})); }
      catch (_) { input.dispatchEvent(new Event('input', {bubbles: true})); }
      input.dispatchEvent(new Event('change', {bubbles: true}));
      input.dispatchEvent(new FocusEvent('blur', {bubbles: true}));
      input.blur();
      input.focus();
      return {ok: true, reason: 'stable_async_enter_click', value: input.value,
        hasForm: true, hasSubmit: true, submitDisabled: !!submit.disabled};
    }
    """
    try:
        result = await page.evaluate(script, {"email": str(email or "").strip()})
        return dict(result) if isinstance(result, Mapping) else {"ok": False, "reason": "invalid_result"}
    except Exception as exc:
        return {"ok": False, "reason": type(exc).__name__}


async def _auth_error_text(page: Any) -> str:
    text = await _page_visible_text(page)
    for token in (
        "Incorrect", "invalid", "Invalid", "account_deactivated", "account_suspended",
        "account_banned", "Authentication Error", "already registered", "already signed up",
        "已有账号",
    ):
        if token in text:
            return token
    return ""


async def _accept_about_you_consents(page: Any, log: Callable[[str, str], None]) -> bool:
    try:
        checkboxes = page.locator("input[type='checkbox']")
        count = await checkboxes.count()
    except Exception:
        return False
    for index in range(count):
        try:
            checkbox = checkboxes.nth(index)
            if not await checkbox.is_visible(timeout=300):
                continue
            if not await checkbox.is_checked():
                await checkbox.check(timeout=3000)
            log("Camoufox 资料页已接受必选隐私条款", "info")
            return True
        except Exception:
            continue
    return False


async def _confirm_birthday(page: Any, log: Callable[[str, str], None], *, timeout: float = 1.0) -> bool:
    selectors = (
        "[role='dialog'] button:has-text('OK')",
        "[role='dialog'] button:has-text('Confirm')",
        "button:has-text('OK')",
    )
    deadline = time.monotonic() + max(0.0, float(timeout))
    while time.monotonic() <= deadline:
        for selector in selectors:
            try:
                locator = page.locator(selector).first
                if await locator.is_visible(timeout=250):
                    await locator.click(timeout=3000)
                    log("Camoufox 资料页已确认生日", "info")
                    return True
            except Exception:
                continue
        await asyncio.sleep(0.2)
    return False


async def _goto_with_retry(
    page: Any,
    url: str,
    *,
    timeout_ms: int,
    proxy_retryable: bool,
) -> Any:
    """Reference-style navigation: preserve usable pages and retry transient disconnects once."""
    last_error: BaseException | None = None
    for attempt in range(2):
        try:
            response = await _goto_with_diagnostics(
                page, url, timeout_ms=timeout_ms, proxy_retryable=proxy_retryable,
            )
            await _wait_challenge_then_stop(page)
            return response
        except CamoufoxBrowserError as exc:
            last_error = exc
            if exc.error_code in {"camoufox_navigation_rate_limited", "camoufox_proxy_blocked"}:
                raise
            if attempt == 0 and proxy_retryable and _browser_process_lost(exc):
                await asyncio.sleep(2)
                continue
            raise
        except Exception as exc:
            last_error = exc
            if attempt == 0 and proxy_retryable and _browser_process_lost(exc):
                await asyncio.sleep(2)
                continue
            raise CamoufoxBrowserError(
                "free_camoufox_navigation", "打开 Camoufox 注册页面",
                "Camoufox 页面导航失败", retryable=bool(proxy_retryable),
                error_code="camoufox_navigation_failed", diagnostic=type(exc).__name__,
                safe_page=_safe_url(page), page_type="navigation",
            ) from exc
    raise CamoufoxBrowserError(
        "free_camoufox_navigation", "打开 Camoufox 注册页面",
        "Camoufox 页面导航失败", retryable=bool(proxy_retryable),
        error_code="camoufox_navigation_failed", diagnostic=type(last_error).__name__ if last_error else "unknown",
        safe_page=_safe_url(page), page_type="navigation",
    ) from last_error


async def _response_retry_after(response: Any) -> int:
    """Read only a numeric Retry-After value; never persist response headers."""
    value: Any = None
    try:
        headers = getattr(response, "headers", None)
        if isinstance(headers, Mapping):
            value = headers.get("retry-after") or headers.get("Retry-After")
    except Exception:
        value = None
    if value is None:
        try:
            value = response.header_value("retry-after")
            if inspect.isawaitable(value):
                value = await value
        except Exception:
            value = None
    try:
        return max(0, min(86400, int(float(str(value or "0").strip()))))
    except (TypeError, ValueError):
        return 0


async def _goto_with_diagnostics(
    page: Any,
    url: str,
    *,
    timeout_ms: int,
    proxy_retryable: bool = False,
) -> Any:
    """Navigate while preserving safe HTTP/proxy diagnostics for the manager."""
    try:
        response = await page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
    except FreeRegisterError:
        raise
    except Exception as exc:
        if _browser_process_lost(exc):
            raise CamoufoxBrowserError(
                "free_camoufox_launch", "启动 Camoufox 浏览器池",
                "Camoufox 浏览器进程已断开",
                retryable=True, error_code="camoufox_browser_disconnected",
                diagnostic="browser process lost", safe_page=_safe_url(page), page_type="unknown",
            ) from exc
        failure = CamoufoxBrowserError(
            "free_camoufox_navigation", "打开 Camoufox 注册页面",
            "Camoufox 页面导航失败",
            retryable=bool(proxy_retryable), error_code="camoufox_navigation_failed",
            diagnostic=type(exc).__name__, safe_page=_safe_url(page), page_type="navigation",
        )
        failure.proxy_retryable = bool(proxy_retryable)
        raise failure from exc

    try:
        status = int(getattr(response, "status", 0) or 0)
    except (TypeError, ValueError):
        status = 0
    retry_after = await _response_retry_after(response)
    body = (await _body_text(page)).casefold()
    blocked = any(marker in body for marker in _PROXY_BLOCK_PAGE_MARKERS)
    if status == 429:
        raise CamoufoxBrowserError(
            "free_camoufox_navigation", "打开 Camoufox 注册页面",
            "Camoufox 页面返回业务限流（429），不会自动重放注册",
            retryable=False, provider_status=429, provider_code="http_429",
            retry_after_seconds=retry_after, error_code="camoufox_navigation_rate_limited",
            diagnostic=f"provider_status=429; retry_after={retry_after}s",
            safe_page=_safe_url(page), page_type="navigation",
        )
    if blocked or status in {403, 407} or status >= 500:
        code = "camoufox_proxy_blocked" if blocked else f"camoufox_navigation_http_{status}"
        failure = CamoufoxBrowserError(
            "free_camoufox_navigation", "打开 Camoufox 注册页面",
            "Camoufox 页面被代理或上游服务阻断",
            retryable=bool(proxy_retryable), provider_status=status or None,
            provider_code=f"http_{status}" if status else "proxy_blocked",
            error_code=code, diagnostic="proxy blocked page" if blocked else f"provider_status={status}",
            safe_page=_safe_url(page), page_type="navigation",
        )
        failure.proxy_retryable = bool(proxy_retryable)
        raise failure
    return response


async def _new_context(
    browser: Any,
    *,
    proxy: dict[str, Any] | None,
) -> Any:
    """Create a fingerprinted context, with a version-compatible fallback."""
    _, AsyncNewContext = _load_camoufox_api()
    context_kwargs = {
        "viewport": {"width": 1024, "height": 720},
        "locale": "en-US",
        "timezone_id": "America/New_York",
        "reduced_motion": "reduce",
        "service_workers": "block",
    }
    try:
        return await AsyncNewContext(
            browser,
            os=random.choice(("windows", "macos")),
            proxy=proxy,
            **context_kwargs,
        )
    except TypeError as exc:
        # Camoufox has changed its fingerprint/context helper signature across
        # releases. Keep registration usable with the same proxy and locale if
        # that helper rejects a keyword; a plain Playwright context is still
        # isolated and is preferable to losing the mailbox before navigation.
        new_context = getattr(browser, "new_context", None)
        if not callable(new_context):
            raise
        # Some Camoufox/Playwright combinations expose a Browser-like object
        # whose generated `new_context` method accepts only the core options.
        # Retry with progressively smaller option sets while preserving the
        # task proxy. This keeps the fallback useful across both API families.
        fallback_options = (
            context_kwargs,
            {key: value for key, value in context_kwargs.items() if key not in {"service_workers"}},
            {key: value for key, value in context_kwargs.items() if key not in {"service_workers", "reduced_motion"}},
            {key: value for key, value in context_kwargs.items() if key in {"viewport", "locale", "timezone_id"}},
            {"locale": context_kwargs["locale"]},
            {},
        )
        last_error: BaseException = exc
        for options in fallback_options:
            try:
                return await new_context(proxy=proxy, **options)
            except TypeError as fallback_exc:
                last_error = fallback_exc
                continue
            except Exception as fallback_exc:
                raise TypeError(
                    f"fingerprint context rejected TypeError; standard context rejected {type(fallback_exc).__name__}"
                ) from exc
        raise TypeError(
            f"fingerprint context rejected TypeError; standard context rejected {type(last_error).__name__}"
        ) from exc


async def _visible(page: Any, selectors: tuple[str, ...], timeout: int = 500) -> Any | None:
    for selector in selectors:
        try:
            locator = page.locator(selector).first
            if await locator.is_visible(timeout=timeout):
                return locator
        except Exception:
            continue
    return None


async def _fill(locator: Any, value: str) -> bool:
    try:
        await locator.click()
        await locator.fill("")
        await locator.fill(str(value))
        return True
    except Exception:
        try:
            await locator.fill(str(value))
            return True
        except Exception:
            return False


async def _click(page: Any, selectors: tuple[str, ...], timeout: int = 2500) -> bool:
    for selector in selectors:
        try:
            locator = page.locator(selector).first
            if await locator.is_visible(timeout=500):
                if await locator.is_enabled(timeout=500):
                    await locator.click(timeout=timeout)
                    return True
        except Exception:
            continue
    return False


async def _submit(locator: Any) -> bool:
    try:
        await locator.press("Enter")
        return True
    except Exception:
        return False


async def _browser_signin_url(page: Any, email: str) -> str:
    """Use ChatGPT's same-origin signin endpoint when the entry form is late."""
    script = """
    async ({email, deviceId}) => {
      try {
        const csrf = await fetch('https://chatgpt.com/api/auth/csrf', {
          credentials: 'include', headers: {accept: 'application/json'}
        });
        const csrfPayload = await csrf.json();
        const csrfToken = String(csrfPayload?.csrfToken || '');
        if (!csrfToken) return {ok: false, url: ''};
        const query = new URLSearchParams({
          prompt: 'login', 'ext-oai-did': deviceId,
          auth_session_logging_id: crypto.randomUUID(),
          screen_hint: 'login_or_signup', login_hint: email
        });
        const body = new URLSearchParams({
          callbackUrl: 'https://chatgpt.com/', csrfToken, json: 'true'
        });
        const response = await fetch(
          'https://chatgpt.com/api/auth/signin/openai?' + query.toString(),
          {method: 'POST', credentials: 'include', redirect: 'follow',
           headers: {'accept': 'application/json', 'content-type': 'application/x-www-form-urlencoded'},
           body: body.toString()}
        );
        const payload = await response.json().catch(() => ({}));
        return {ok: response.ok, url: String(payload?.url || '')};
      } catch (_) {
        return {ok: false, url: ''};
      }
    }
    """
    try:
        result = await page.evaluate(script, {"email": str(email), "deviceId": str(uuid.uuid4())})
    except Exception:
        return ""
    return str(result.get("url") or "").strip() if isinstance(result, Mapping) and result.get("ok") else ""


async def _page_state(page: Any) -> str:
    raw_url = str(getattr(page, "url", "") or "")
    parsed = urlsplit(raw_url)
    host = (parsed.hostname or "").casefold()
    path = (parsed.path or "/").casefold().rstrip("/") or "/"
    body = (await _body_text(page)).casefold()
    if any(marker in body for marker in ("cloudflare", "verify you are human", "turnstile", "just a moment", "安全验证")):
        return "security"
    if host == "chatgpt.com" and path in {"", "/"}:
        return "home"
    if host == "chatgpt.com" and ("/auth/login" in path or "/login" in path):
        if await _visible(page, PASSWORD_SELECTORS, 250):
            return "login_password"
        if await _visible(page, OTP_SELECTORS, 250):
            return "otp"
        return "entry"
    if "auth.openai.com" in host:
        if any(marker in path for marker in ("/about-you", "/about_you", "/birthdate", "/profile")):
            return "profile"
        if path in {"/log-in/password", "/login/password"}:
            return "login_password"
        if "password" in path or "new-password" in path:
            return "signup_password"
        if any(marker in path for marker in ("email-verification", "email-otp", "/verify")):
            if await _visible(page, PASSWORD_SELECTORS, 250):
                return "signup_password"
            return "otp" if await _visible(page, OTP_SELECTORS, 250) else "otp_wait"
        if any(marker in path for marker in ("/authorize", "/callback", "/continue")):
            return "oauth_callback"
    if await _visible(page, PASSWORD_SELECTORS, 250):
        return "signup_password"
    if await _visible(page, OTP_SELECTORS, 250):
        return "otp"
    if await _visible(page, NAME_SELECTORS, 250) or await _visible(page, BIRTHDAY_SELECTORS, 250):
        return "profile"
    return "unknown"


async def _wait_state(page: Any, timeout: float, *states: str) -> str:
    deadline = time.monotonic() + max(1.0, float(timeout))
    wanted = set(states)
    current = "unknown"
    while time.monotonic() < deadline:
        current = await _page_state(page)
        if current in wanted:
            return current
        await asyncio.sleep(0.35)
    return current


async def _accept_consents(page: Any) -> None:
    try:
        checkboxes = page.locator("input[type='checkbox']")
        count = await checkboxes.count()
    except Exception:
        return
    for index in range(count):
        try:
            item = checkboxes.nth(index)
            if await item.is_visible(timeout=250) and not await item.is_checked():
                await item.check(timeout=2500)
        except Exception:
            continue


async def _complete_profile(page: Any, log: Callable[[str, str], None]) -> None:
    name = await _visible(page, NAME_SELECTORS)
    if name:
        await _fill(name, random_display_name())
    age = await _visible(page, AGE_SELECTORS)
    if age:
        await _fill(age, "25")
    birthday = await _visible(page, BIRTHDAY_SELECTORS)
    if birthday:
        await _fill(birthday, random_birthdate())
    await _accept_consents(page)
    if not await _click(page, PROFILE_SUBMIT_SELECTORS, timeout=5000):
        if name:
            await _submit(name)
    log("Camoufox 资料页已提交", "info")


async def _browser_flow(
    page: Any,
    *,
    email: str,
    password: str,
    proxy: str = "",
    otp_callback: Callable[[], str],
    config: Mapping[str, Any],
    log: Callable[[str, str], None],
    otp_prepare: Callable[..., Any] | None = None,
    otp_mark_sent: Callable[..., Any] | None = None,
    stage_fn: Callable[[str, str], None] | None = None,
    force_existing_login: bool = False,
) -> dict[str, Any]:
    timeout = max(60, int(config.get("registration_timeout_seconds") or 600))
    deadline = time.monotonic() + timeout
    account_flow = "existing_login" if force_existing_login else "signup"
    password_used = False
    entry_submitted = False
    controlled_entry_resubmit = False
    otp_submitted = False
    otp_submitted_at = 0.0
    otp_resend_used = False
    otp_input_selector = ""
    password_submitted_at = 0.0
    profile_submitted = False
    email_continue_clicked = False
    entry_transition_deadline = 0.0
    browser_signin_fallback_used = False
    seen: dict[str, int] = {}

    def set_stage(code: str) -> None:
        if callable(stage_fn):
            stage_fn(str(config.get("task_id") or ""), code)

    async def prepare_otp(stage_code: str) -> None:
        if not callable(otp_prepare):
            return
        try:
            await asyncio.to_thread(otp_prepare, stage_code, force_snapshot=True)
        except TypeError as exc:
            # Only retry a provider signature mismatch. A TypeError raised by
            # the provider itself must remain visible to the stage classifier.
            try:
                await asyncio.to_thread(otp_prepare, stage_code)
            except TypeError:
                raise CamoufoxBrowserError(
                    stage_code, "准备 Free 邮箱验证码", "邮箱 provider 准备阶段失败",
                    error_code=f"{stage_code}_prepare_failed", diagnostic=type(exc).__name__,
                ) from exc

    async def mark_otp_sent(stage_code: str) -> None:
        if callable(otp_mark_sent):
            await asyncio.to_thread(otp_mark_sent, stage_code)

    async def wait_for_state(*states: str, seconds: float = 45.0) -> str:
        remaining = max(1.0, deadline - time.monotonic())
        return await _wait_state(page, min(float(seconds), remaining), *states)

    async def finish_home() -> dict[str, Any]:
        session = await browser_session(page)
        set_stage("free_access_token")
        token = str(session.get("accessToken") or "")
        accounts_url = CHATGPT_ACCOUNTS_URL
        if "?" not in accounts_url:
            accounts_url += "?timezone_offset_min=-"
        accounts = await browser_json_fetch(page, accounts_url, token=token)
        eligibility = await browser_json_fetch(page, CHATGPT_ELIGIBILITY_URL, token=token)
        plan = plan_details_from_payloads(accounts, eligibility)
        set_stage("free_plan_check")
        result: dict[str, Any] = {
            "access_token": token,
            "has_access_token": bool(token),
            "account_flow": account_flow,
            "registration_password_used": password_used,
            **plan,
        }
        if bool(config.get("auto_set_2fa", True)):
            set_stage("free_twofa_enroll")
            try:
                secret = await browser_twofa(page, token)
                set_stage("free_twofa_activate")
                result.update({"totp_secret": secret, "twofa_status": "enabled"})
            except FreeRegisterError as exc:
                result.update({
                    "twofa_status": "pending",
                    "twofa_error": clean(str(exc), 300),
                    "twofa_failure": {
                        "node_code": exc.node_code, "node_label": exc.node_label,
                        "error_code": exc.error_code,
                        "public_message": f"{exc.node_label} [{exc.node_label}/{exc.node_code}]：{clean(str(exc), 300)}",
                        "retryable": bool(exc.retryable), "provider_code": exc.provider_code,
                    },
                })
        else:
            result["twofa_status"] = "disabled"
        return finalize_registration_result(
            result, driver="camoufox", email=email, password_used=password_used,
        )

    # Match the reference flow: establish the mailbox baseline before the
    # first request that may send an OTP, then wait for the actual DOM entry.
    if force_existing_login:
        await prepare_otp("free_existing_login_otp")
    await _goto_with_retry(
        page, CHATGPT_LOGIN_URL, timeout_ms=min(timeout * 1000, 90_000),
        proxy_retryable=not force_existing_login,
    )
    await asyncio.sleep(1.5)
    email_selector = await _wait_for_any_selector(page, EMAIL_SELECTORS, timeout=12)
    if email_selector:
        set_stage("free_existing_login_otp" if force_existing_login else "free_camoufox_signup_email")
        if not force_existing_login:
            await prepare_otp("free_email_otp_wait")
        if not await _fill_input_like_user(page, email_selector, email):
            raise CamoufoxBrowserError(
                "free_camoufox_signup_email", "填写 Camoufox 注册邮箱", "邮箱输入框写入失败",
                error_code="camoufox_email_fill_failed",
            )
        stable_submit = await _submit_email_form_stable(page, email)
        log(
            f"Camoufox 邮箱稳定提交：{clean(stable_submit.get('reason'), 80)}",
            "info",
        )
        if stable_submit.get("ok"):
            if not await _submit_visible_form(page, email_selector):
                submit_selector = await _click_first(page, SUBMIT_SELECTORS, timeout=5)
        else:
            submit_selector = await _click_first(page, SUBMIT_SELECTORS, timeout=5)
            if not submit_selector:
                await _submit_visible_form(page, email_selector)
        entry_submitted = True
        entry_transition_deadline = time.monotonic() + 45.0
    else:
        # Keep the same-origin NextAuth fallback from the reference flow for a
        # delayed shell, but never invent an external provider URL.
        if not force_existing_login:
            await prepare_otp("free_email_otp_wait")
        authorize_url = await _browser_signin_url(page, email)
        if authorize_url:
            await _goto_with_retry(
                page, authorize_url, timeout_ms=min(timeout * 1000, 90_000),
                proxy_retryable=False,
            )
            entry_submitted = True
        else:
            snapshot = await _snapshot(page)
            raise CamoufoxBrowserError(
                "free_camoufox_navigation", "打开 Camoufox 注册页面",
                "登录页未找到邮箱输入框，当前代理返回了不可用页面",
                retryable=True, error_code="camoufox_entry_form_missing",
                diagnostic=json.dumps(snapshot, ensure_ascii=False)[:500],
                safe_page=snapshot.get("url"), page_type="entry",
            )

    while time.monotonic() < deadline:
        state = await _page_state(page)
        seen[state] = seen.get(state, 0) + 1
        if seen[state] > 12 and state in {"unknown", "entry"}:
            if state == "entry" and entry_submitted and time.monotonic() < entry_transition_deadline:
                await asyncio.sleep(1.0)
                continue
            if state == "entry" and entry_submitted and not browser_signin_fallback_used:
                browser_signin_fallback_used = True
                authorize_url = await _browser_signin_url(page, email)
                if authorize_url:
                    await _goto_with_retry(
                        page, authorize_url, timeout_ms=min(timeout * 1000, 90_000),
                        proxy_retryable=False,
                    )
                    entry_transition_deadline = time.monotonic() + 45.0
                    seen.clear()
                    continue
            error_text = await _auth_error_text(page)
            snapshot = await _snapshot(page)
            raise CamoufoxBrowserError(
                "free_camoufox_navigation", "打开 Camoufox 注册页面",
                error_text or "注册页面状态长时间未推进",
                retryable=not entry_submitted,
                error_code="camoufox_entry_transition_timeout" if entry_submitted else "camoufox_entry_state_stuck",
                diagnostic=json.dumps(snapshot, ensure_ascii=False)[:500],
                safe_page=snapshot.get("url"), page_type=state,
            )
        if state == "security":
            await _wait_challenge_then_stop(page, timeout=30)
        if state == "home":
            return await finish_home()

        if state == "entry":
            if not entry_submitted:
                selector = await _wait_for_any_selector(page, EMAIL_SELECTORS, timeout=8)
                if selector:
                    set_stage("free_camoufox_signup_email")
                    await prepare_otp("free_email_otp_wait")
                    if not await _fill_input_like_user(page, selector, email):
                        raise CamoufoxBrowserError("free_camoufox_signup_email", "填写 Camoufox 注册邮箱", "邮箱输入框写入失败", error_code="camoufox_email_fill_failed")
                    await _click_first(page, SUBMIT_SELECTORS, timeout=5)
                    await _submit_visible_form(page, selector)
                    entry_submitted = True
            elif not controlled_entry_resubmit:
                selector = await _find_visible_selector(page, EMAIL_SELECTORS)
                stable_submit = await _submit_email_form_stable(page, email)
                if stable_submit.get("ok"):
                    if selector and not await _submit_visible_form(page, selector):
                        await _click_first(page, SUBMIT_SELECTORS, timeout=5)
                else:
                    if selector:
                        await _submit_visible_form(page, selector)
                controlled_entry_resubmit = True
                entry_transition_deadline = time.monotonic() + 45.0
            await asyncio.sleep(1.0)
            continue

        if state == "login_password":
            if not bool(config.get("existing_account_login", True)):
                raise CamoufoxBrowserError(
                    "free_existing_login", "已有 Free 账号登录",
                    "邮箱已存在账号，Camoufox 未开启已有账号邮箱验证码登录",
                    retryable=False, error_code="free_existing_login_disabled",
                )
            account_flow = "existing_login"
            set_stage("free_existing_login_otp")
            await prepare_otp("free_existing_login_otp")
            if not await _click_first(page, PASSWORDLESS_SELECTORS, timeout=8):
                raise CamoufoxBrowserError(
                    "free_existing_login", "已有 Free 账号登录",
                    "登录密码页未找到邮箱验证码入口", retryable=False,
                    error_code="free_camoufox_login_password_page",
                )
            await asyncio.sleep(1.0)
            continue

        if state == "signup_password":
            set_stage("free_camoufox_signup_password")
            selector = await _wait_for_any_selector(page, PASSWORD_SELECTORS, timeout=15)
            if not selector or not await _fill_input_like_user(page, selector, password):
                raise CamoufoxBrowserError(
                    "free_camoufox_signup_password", "提交 Camoufox 注册密码", "注册密码输入失败",
                    error_code="camoufox_password_fill_failed",
                )
            if not await _click_first(page, SUBMIT_SELECTORS, timeout=6):
                await _submit_visible_form(page, selector)
            password_used = True
            password_submitted_at = time.monotonic()
            await asyncio.sleep(1.0)
            continue

        if state in {"otp", "otp_wait"}:
            stage_code = "free_existing_login_otp" if account_flow == "existing_login" else "free_email_otp_wait"
            set_stage(stage_code)
            if not otp_submitted:
                if entry_submitted or account_flow == "existing_login":
                    await mark_otp_sent(stage_code)
                try:
                    code = str(await asyncio.to_thread(otp_callback, stage_code) or "").strip()
                except TypeError:
                    code = str(await asyncio.to_thread(otp_callback) or "").strip()
                if not code:
                    raise CamoufoxBrowserError(
                        "free_email_otp_wait", "等待 Free 邮箱验证码", "未获取到邮箱验证码",
                        error_code="camoufox_otp_missing",
                    )
                selector = await _wait_for_any_selector(page, OTP_SELECTORS, timeout=15)
                if not selector or not await _fill_input_like_user(page, selector, code):
                    raise CamoufoxBrowserError(
                        "free_email_otp_validate", "验证 Free 邮箱验证码", "验证码输入框不可用",
                        error_code="camoufox_otp_input_missing",
                    )
                otp_input_selector = selector
                if not await _click_first(page, SUBMIT_SELECTORS, timeout=6):
                    await _submit_visible_form(page, selector)
                otp_submitted = True
                otp_submitted_at = time.monotonic()
                await asyncio.sleep(1.0)
                continue
            elapsed = time.monotonic() - otp_submitted_at
            if elapsed >= 60:
                if otp_resend_used:
                    raise CamoufoxBrowserError(
                        "free_email_otp_validate", "验证 Free 邮箱验证码",
                        "验证码提交后页面未继续", error_code="camoufox_otp_transition_timeout",
                    )
                await prepare_otp(stage_code)
                if not await _click_first(page, RESEND_SELECTORS, timeout=5):
                    raise CamoufoxBrowserError(
                        "free_email_otp_validate", "验证 Free 邮箱验证码",
                        "验证码提交后页面未继续，未找到受控重发入口",
                        error_code="camoufox_otp_resend_unavailable",
                    )
                await mark_otp_sent(stage_code)
                otp_submitted = False
                otp_resend_used = True
                continue
            await asyncio.sleep(1.0)
            continue

        if state == "profile":
            set_stage("free_camoufox_profile")
            if not profile_submitted:
                name = await _find_visible_selector(page, NAME_SELECTORS)
                if name:
                    await _fill_input_like_user(page, name, random_display_name())
                age = await _find_visible_selector(page, AGE_SELECTORS)
                if age:
                    await _fill_input_like_user(page, age, "25")
                birthday = await _find_visible_selector(page, BIRTHDAY_SELECTORS)
                if birthday:
                    await _fill_input_like_user(page, birthday, random_birthdate())
                await _accept_about_you_consents(page, log)
                submit_selector = await _wait_for_submit_enabled(page, PROFILE_SUBMIT_SELECTORS, timeout=25)
                if not submit_selector:
                    raise CamoufoxBrowserError(
                        "free_camoufox_profile", "填写 Camoufox 账号资料",
                        "资料页提交按钮长时间不可用", error_code="camoufox_profile_submit_unavailable",
                    )
                await _click_first(page, (submit_selector,), timeout=8)
                profile_submitted = True
                await _confirm_birthday(page, log, timeout=5)
            await asyncio.sleep(1.0)
            continue

        if state == "oauth_callback":
            await asyncio.sleep(1.0)
            continue

        if state == "security":
            raise CamoufoxBrowserError(
                "free_camoufox_challenge", "等待 Camoufox 安全验证",
                "注册流程进入安全验证，已停止自动操作", retryable=False,
                error_code="free_camoufox_security_challenge",
            )
        error_text = await _auth_error_text(page)
        if error_text:
            raise CamoufoxBrowserError(
                "free_camoufox_navigation", "打开 Camoufox 注册页面", error_text,
                retryable=not entry_submitted, error_code="camoufox_auth_page_error",
                safe_page=_safe_url(page), page_type=state,
            )
        await asyncio.sleep(1.0)

    raise CamoufoxBrowserError(
        "free_camoufox_page_state", "确认 ChatGPT 登录首页",
        "注册状态机超时，页面未确认进入首页", error_code="camoufox_home_not_confirmed",
        safe_page=_safe_url(page), page_type=await _page_state(page),
    )


@dataclass
class _BrowserSlot:
    manager: Any
    browser: Any
    semaphore: asyncio.Semaphore
    completed: int = 0
    generation: int = 0
    recycle_lock: asyncio.Lock | None = None
    idle_event: asyncio.Event | None = None
    active_contexts: int = 0
    draining: bool = False
    recycle_error: str = ""


class CamoufoxBrowserPool:
    """Dedicated asyncio thread with shared browsers and bounded contexts."""

    def __init__(self, config: Mapping[str, Any]) -> None:
        self.config = dict(config)
        self.headless = bool(self.config.get("headless", True))
        self.pool_size = max(1, int(self.config.get("pool_size") or 2))
        self.max_contexts = max(1, int(self.config.get("max_contexts_per_browser") or 3))
        self.context_start_interval = max(0, int(self.config.get("context_start_interval_ms") or 0)) / 1000.0
        self.startup_concurrency = max(1, int(self.config.get("startup_concurrency") or 4))
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._ready = threading.Event()
        self._closed = False
        self._init_error: BaseException | None = None
        self._slots: list[_BrowserSlot] = []
        self._global_semaphore: asyncio.Semaphore | None = None
        self._startup_semaphore: asyncio.Semaphore | None = None
        self._context_start_lock: asyncio.Lock | None = None
        self._next_context_start = 0.0
        self._lock = threading.Lock()
        self._start()

    def _start(self) -> None:
        def target() -> None:
            self._loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._loop)
            try:
                self._loop.run_until_complete(self._init_async())
            except BaseException as exc:
                self._init_error = exc
            finally:
                self._ready.set()
            if self._init_error is None:
                try:
                    self._loop.run_forever()
                finally:
                    self._loop.run_until_complete(self._shutdown_async())
                    self._cancel_pending_tasks()
            else:
                # Initialization may have opened some managers before a later
                # slot failed. Reclaim those partial resources before the
                # dependency/startup error reaches the caller.
                self._loop.run_until_complete(self._shutdown_async())
                self._cancel_pending_tasks()
            self._loop.close()
        self._thread = threading.Thread(target=target, name="gptphone-camoufox", daemon=True)
        self._thread.start()
        self._ready.wait(timeout=90)

    def _cancel_pending_tasks(self) -> None:
        if self._loop is None:
            return
        pending = [task for task in asyncio.all_tasks(self._loop) if not task.done()]
        for task in pending:
            task.cancel()
        if pending:
            self._loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))

    async def _init_async(self) -> None:
        AsyncCamoufox, _ = _load_camoufox_api()
        self._global_semaphore = asyncio.Semaphore(self.pool_size * self.max_contexts)
        self._startup_semaphore = asyncio.Semaphore(min(self.startup_concurrency, self.pool_size * self.max_contexts))
        self._context_start_lock = asyncio.Lock()
        for _index in range(self.pool_size):
            manager, browser = await self._launch_browser()
            self._slots.append(_BrowserSlot(
                manager, browser, asyncio.Semaphore(self.max_contexts),
                recycle_lock=asyncio.Lock(), idle_event=asyncio.Event(),
            ))
            self._slots[-1].idle_event.set()

    async def _launch_browser(self) -> tuple[Any, Any]:
        AsyncCamoufox, _ = _load_camoufox_api()
        last_error: BaseException | None = None
        attempts = max(1, int(self.config.get("browser_launch_attempts") or 3))
        for attempt in range(attempts):
            launch_options = {
                "headless": self.headless,
                "block_images": bool(self.config.get("block_images", True) and self.headless),
                "enable_cache": False,
            }
            if launch_options["block_images"]:
                # Camoufox requires an explicit acknowledgement because image
                # blocking can affect WAF detection and page behavior.
                launch_options["i_know_what_im_doing"] = True
            manager = AsyncCamoufox(
                **launch_options,
            )
            try:
                if self._startup_semaphore is None:
                    browser = await manager.__aenter__()
                else:
                    async with self._startup_semaphore:
                        browser = await manager.__aenter__()
                return manager, browser
            except BaseException as exc:
                last_error = exc
                try:
                    await manager.__aexit__(type(exc), exc, exc.__traceback__)
                except Exception:
                    pass
                if attempt + 1 < attempts:
                    await asyncio.sleep(min(2 ** attempt, 5))
        raise CamoufoxBrowserError(
            "free_camoufox_launch", "启动 Camoufox 浏览器池",
            "Camoufox 浏览器进程启动失败",
            error_code="camoufox_browser_launch_failed",
            diagnostic=type(last_error).__name__ if last_error else "unknown",
        ) from last_error

    async def _shutdown_async(self) -> None:
        slots, self._slots = self._slots, []
        for slot in slots:
            try:
                manager = slot.manager
                browser = slot.browser
                if manager is not None:
                    await asyncio.wait_for(manager.__aexit__(None, None, None), timeout=float(self.config.get("browser_recycle_timeout_seconds") or 45))
                elif browser is not None:
                    await asyncio.wait_for(browser.close(), timeout=float(self.config.get("context_close_timeout_seconds") or 15))
            except Exception:
                try:
                    if slot.browser is not None:
                        await slot.browser.close()
                except Exception:
                    pass

    async def _register_async(self, kwargs: Mapping[str, Any]) -> dict[str, Any]:
        if self._global_semaphore is None or not self._slots:
            raise CamoufoxBrowserError("free_camoufox_launch", "启动 Camoufox", "浏览器池没有可用进程", error_code="camoufox_pool_empty")
        try:
            async with self._global_semaphore:
                return await asyncio.wait_for(
                    self._register_with_slot(kwargs),
                    timeout=float(self.config.get("registration_timeout_seconds") or 600),
                )
        except asyncio.TimeoutError as exc:
            raise CamoufoxBrowserError(
                "free_camoufox_browser", "Camoufox 注册页面",
                "浏览器注册超时，已取消当前 context 并回收进程",
                error_code="camoufox_registration_timeout",
            ) from exc

    @staticmethod
    def _browser_connected(browser: Any) -> bool:
        try:
            checker = getattr(browser, "is_connected", None)
            return bool(checker()) if callable(checker) else browser is not None
        except Exception:
            return False

    async def _wait_context_start_slot(self) -> None:
        if self.context_start_interval <= 0 or self._context_start_lock is None:
            return
        async with self._context_start_lock:
            now = asyncio.get_running_loop().time()
            if self._next_context_start > now:
                await asyncio.sleep(self._next_context_start - now)
            self._next_context_start = asyncio.get_running_loop().time() + self.context_start_interval

    async def _register_with_slot(self, kwargs: Mapping[str, Any]) -> dict[str, Any]:
        available = [slot for slot in self._slots if not slot.draining and self._browser_connected(slot.browser)]
        if not available:
            recycle_errors = [slot.recycle_error for slot in self._slots if slot.recycle_error]
            if recycle_errors:
                raise CamoufoxBrowserError(
                    "free_camoufox_launch", "启动 Camoufox 浏览器池",
                    "Camoufox 浏览器进程回收后重新启动失败",
                    retryable=True, error_code="camoufox_browser_recycle_failed",
                    diagnostic=recycle_errors[0],
                )
            raise CamoufoxBrowserError("free_camoufox_launch", "启动 Camoufox", "浏览器池没有可用进程", error_code="camoufox_browser_disconnected")
        idle = [item for item in available if not item.semaphore.locked()]
        slot = min(idle or available, key=lambda item: (item.active_contexts, item.completed))
        async with slot.semaphore:
            if slot.draining or not self._browser_connected(slot.browser):
                raise CamoufoxBrowserError("free_camoufox_launch", "启动 Camoufox", "浏览器进程已断开", error_code="camoufox_browser_disconnected")
            slot.active_contexts += 1
            if slot.idle_event is not None:
                slot.idle_event.clear()
            generation = slot.generation
            context = None
            recycle_required = False
            try:
                await self._wait_context_start_slot()
                try:
                    context = await _new_context(
                        slot.browser,
                        proxy=_proxy_config(str(kwargs.get("proxy") or "")),
                    )
                except CamoufoxBrowserError:
                    raise
                except Exception as exc:
                    if _browser_process_lost(exc):
                        recycle_required = True
                        raise CamoufoxBrowserError(
                            "free_camoufox_launch", "创建 Camoufox 浏览器 context",
                            "Camoufox 浏览器进程无法创建 context",
                            error_code="camoufox_context_create_failed",
                            diagnostic="browser process lost",
                        ) from exc
                    raise CamoufoxBrowserError(
                        "free_camoufox_launch", "创建 Camoufox 浏览器 context",
                        "Camoufox context 创建失败",
                        error_code="camoufox_context_create_failed",
                        diagnostic=type(exc).__name__,
                    ) from exc
                try:
                    page = await context.new_page()
                except Exception as exc:
                    if _browser_process_lost(exc):
                        recycle_required = True
                        raise CamoufoxBrowserError(
                            "free_camoufox_launch", "创建 Camoufox 注册页面",
                            "Camoufox 浏览器进程无法创建页面",
                            error_code="camoufox_page_create_failed",
                            diagnostic="browser process lost",
                        ) from exc
                    raise CamoufoxBrowserError(
                        "free_camoufox_launch", "创建 Camoufox 注册页面",
                        "Camoufox context 无法创建页面",
                        error_code="camoufox_page_create_failed",
                        diagnostic=type(exc).__name__,
                    ) from exc
                result = await _browser_flow(page, **kwargs)
                slot.completed += 1
                recycle_required = slot.completed >= max(1, int(self.config.get("max_registrations_per_browser") or 12))
                return result
            except asyncio.CancelledError:
                # A registration timeout cancels the page coroutine. Recycle
                # the process even when context.close() itself succeeds: the
                # page may have left unfinished navigation callbacks behind.
                recycle_required = True
                raise
            except FreeRegisterError:
                raise
            except Exception as exc:
                snapshot = await _snapshot(page) if "page" in locals() else {"url": "", "title": "", "body": ""}
                if _browser_process_lost(exc):
                    recycle_required = True
                    raise CamoufoxBrowserError(
                        "free_camoufox_launch", "启动 Camoufox 浏览器池",
                        "Camoufox 浏览器进程已断开",
                        error_code="camoufox_browser_disconnected",
                        diagnostic="browser process lost",
                        safe_page=snapshot.get("url"), page_type="unknown",
                    ) from exc
                raise CamoufoxBrowserError(
                    "free_camoufox_browser", "Camoufox 注册页面", f"浏览器流程异常（{type(exc).__name__}）",
                    error_code="camoufox_browser_flow_failed",
                    diagnostic=json.dumps({
                        "exception": type(exc).__name__,
                        "detail": _camoufox_error_detail(exc),
                        "kwargs": sorted(str(key) for key in kwargs.keys()),
                        "snapshot": snapshot,
                    }, ensure_ascii=False)[:500],
                    safe_page=snapshot.get("url"), page_type="unknown",
                ) from exc
            finally:
                if context is not None:
                    try:
                        await asyncio.wait_for(context.close(), timeout=float(self.config.get("context_close_timeout_seconds") or 15))
                    except Exception:
                        recycle_required = True
                slot.active_contexts = max(0, slot.active_contexts - 1)
                if slot.active_contexts == 0 and slot.idle_event is not None:
                    slot.idle_event.set()
                if recycle_required and generation == slot.generation and not self._closed:
                    await self._recycle_slot(slot, generation, "达到单进程注册上限或 context 关闭异常")

    async def _recycle_slot(self, slot: _BrowserSlot, generation: int, reason: str) -> None:
        lock = slot.recycle_lock
        if lock is None:
            return
        async with lock:
            if slot.generation != generation or self._closed:
                return
            slot.draining = True
            if slot.active_contexts and slot.idle_event is not None:
                try:
                    await asyncio.wait_for(slot.idle_event.wait(), timeout=float(self.config.get("browser_recycle_drain_timeout_seconds") or 20))
                except asyncio.TimeoutError:
                    pass
            old_manager, old_browser = slot.manager, slot.browser
            slot.manager = None
            slot.browser = None
            slot.generation += 1
            slot.completed = 0
            try:
                if old_manager is not None:
                    await asyncio.wait_for(old_manager.__aexit__(None, None, None), timeout=float(self.config.get("browser_recycle_timeout_seconds") or 45))
                elif old_browser is not None:
                    await asyncio.wait_for(old_browser.close(), timeout=float(self.config.get("context_close_timeout_seconds") or 15))
            except Exception:
                try:
                    await asyncio.wait_for(old_browser.close(), timeout=float(self.config.get("context_close_timeout_seconds") or 15))
                except Exception:
                    pass
            if self._closed:
                return
            try:
                manager, browser = await asyncio.wait_for(self._launch_browser(), timeout=float(self.config.get("browser_recycle_timeout_seconds") or 45))
            except Exception as exc:
                slot.draining = True
                error_code = str(getattr(exc, "error_code", "") or type(exc).__name__)
                slot.recycle_error = clean(f"{error_code}: {type(exc).__name__}", 240)
                return
            slot.manager, slot.browser, slot.draining, slot.recycle_error = manager, browser, False, ""

    def register(self, **kwargs: Any) -> dict[str, Any]:
        if self._closed:
            raise CamoufoxBrowserError("free_camoufox_launch", "启动 Camoufox", "浏览器池已关闭", error_code="camoufox_pool_closed")
        if not self._ready.is_set():
            self._ready.wait(timeout=90)
        if self._init_error:
            if isinstance(self._init_error, (CamoufoxDependencyError, CamoufoxBrowserError)):
                raise self._init_error
            raise CamoufoxBrowserError(
                "free_camoufox_launch", "启动 Camoufox", "浏览器池初始化失败",
                error_code="camoufox_pool_init_failed",
                diagnostic=_camoufox_error_detail(self._init_error),
            ) from self._init_error
        if self._loop is None:
            raise CamoufoxBrowserError("free_camoufox_launch", "启动 Camoufox", "浏览器事件循环不可用", error_code="camoufox_loop_missing")
        future = asyncio.run_coroutine_threadsafe(self._register_async(kwargs), self._loop)
        registration_timeout = float(self.config.get("registration_timeout_seconds") or 600)
        cleanup_budget = float(self.config.get("context_close_timeout_seconds") or 15)
        recycle_budget = float(self.config.get("browser_recycle_timeout_seconds") or 45)
        try:
            return dict(future.result(timeout=registration_timeout + cleanup_budget + recycle_budget + 30))
        except FutureTimeoutError as exc:
            future.cancel()
            raise CamoufoxBrowserError("free_camoufox_browser", "Camoufox 注册页面", "浏览器注册超时", error_code="camoufox_registration_timeout") from exc

    def shutdown(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            if self._loop is not None:
                self._loop.call_soon_threadsafe(self._loop.stop)
        if self._thread is not None:
            self._thread.join(timeout=float(self.config.get("browser_recycle_timeout_seconds") or 45) + 5)


def _proxy_config(proxy: str) -> dict[str, Any] | None:
    value = str(proxy or "").strip()
    if not value:
        return None
    return {"server": value}


_POOL_LOCK = threading.RLock()
_POOLS: dict[tuple[Any, ...], CamoufoxBrowserPool] = {}


def _pool_for(config: Mapping[str, Any]) -> CamoufoxBrowserPool:
    key = (
        bool(config.get("headless", True)), int(config.get("pool_size") or 2),
        int(config.get("max_contexts_per_browser") or 3), bool(config.get("block_images", True)),
        int(config.get("context_start_interval_ms") or 175),
        int(config.get("startup_concurrency") or 4),
        int(config.get("max_registrations_per_browser") or 12),
        int(config.get("browser_launch_attempts") or 3),
    )
    with _POOL_LOCK:
        pool = _POOLS.get(key)
        if pool is None or pool._closed:
            if pool is not None:
                pool.shutdown()
            pool = CamoufoxBrowserPool(config)
            _POOLS[key] = pool
        return pool


def shutdown_camoufox_pools() -> None:
    with _POOL_LOCK:
        pools = list(_POOLS.values())
        _POOLS.clear()
    for pool in pools:
        pool.shutdown()


atexit.register(shutdown_camoufox_pools)


class CamoufoxRegistrationRunner:
    """Manager-compatible synchronous facade for the async browser pool."""

    def __init__(self, *, lifecycle_store_path: str = "") -> None:
        self.lifecycle_store_path = lifecycle_store_path

    @staticmethod
    def preflight(config: Mapping[str, Any]) -> dict[str, Any]:
        _load_camoufox_api()
        runtime_version = _check_camoufox_runtime()
        browser = dict(config.get("camoufox") or {})
        return {
            "driver": "camoufox",
            "dependency": "available",
            "runtime_version": runtime_version,
            "headless": bool(browser.get("headless", True)),
            "pool_size": int(browser.get("pool_size") or 2),
            "max_contexts_per_browser": int(browser.get("max_contexts_per_browser") or 3),
        }

    def __call__(self, task: Mapping[str, Any], config: Mapping[str, Any], stop_event: Any, stage: Callable[[str, str], None], log: Callable[[str, str], None], *, twofa_retry: bool = False) -> Mapping[str, Any]:
        task_id = str(task.get("task_id") or "")
        browser_config = dict(config.get("camoufox") or {})
        otp = build_free_mailbox_otp_provider(
            str(task.get("mailbox_url") or ""), str(task.get("proxy") or ""), config,
            log_fn=log, task_id=task_id, stage_fn=stage,
        )
        try:
            stage(task_id, "free_camoufox_signup")
            if stop_event.is_set():
                raise FreeRegisterError("free_run_stop", "停止 Free 注册", "任务在启动 Camoufox 前已停止", retryable=False)
            def callback(stage_code: str = "free_email_otp_wait") -> str:
                return otp.wait_code(str(task.get("email") or ""), stage_code=stage_code)
            result = _pool_for(browser_config).register(
                email=str(task.get("email") or ""), password=FIXED_PASSWORD,
                proxy=str(task.get("proxy") or ""), otp_callback=callback,
                otp_prepare=otp.prepare, otp_mark_sent=otp.mark_sent,
                config={**config, **browser_config, "task_id": task_id}, log=log,
                stage_fn=stage,
                force_existing_login=twofa_retry,
            )
            result = dict(result)
            result["registration_ip"] = str(task.get("expected_exit_ip") or task.get("exit_ip") or "")
            result["expected_exit_ip"] = str(task.get("expected_exit_ip") or task.get("exit_ip") or "")
            result["profile_summary"] = "Camoufox shared pool"
            return finalize_registration_result(result, driver="camoufox", email=str(task.get("email") or ""))
        finally:
            close = getattr(otp, "close", None)
            if callable(close):
                try:
                    close()
                except Exception:
                    log("Camoufox 邮箱 OTP 客户端清理失败，不覆盖原任务结果", "warn")


__all__ = [
    "CamoufoxBrowserError", "CamoufoxDependencyError", "CamoufoxRegistrationRunner",
    "CamoufoxBrowserPool", "shutdown_camoufox_pools",
]
