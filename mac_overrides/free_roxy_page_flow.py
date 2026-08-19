"""Credential-free page state handling for the Free RoxyBrowser flow."""

from __future__ import annotations

import time
from typing import Any, Callable, Mapping

try:
    from .free_register_common import FreeRegisterError, clean
    from .free_roxy_signup import is_email_verification_page, safe_page_location
except ImportError:
    from free_register_common import FreeRegisterError, clean  # type: ignore[no-redef]
    from free_roxy_signup import is_email_verification_page, safe_page_location  # type: ignore[no-redef]


LogFn = Callable[[str, str], None]


def page_snapshot(driver: Any) -> dict[str, Any]:
    """Return only page metadata that is safe to include in diagnostics."""
    url = safe_page_location(driver)
    body = ""
    try:
        body = str(driver.find_element("tag name", "body").text or "")[:1800]
    except Exception:
        pass
    try:
        result = driver.execute_script("""
          return {title: document.title || '',
            body: (document.body && document.body.innerText || '').slice(0, 1800),
            inputs: [...document.querySelectorAll('input,select,textarea')].filter(el => {
              const r = el.getBoundingClientRect(); return r.width > 0 && r.height > 0;
            }).slice(0, 24).map(el => ({tag: el.tagName, type: el.type || '', name: el.name || '',
              id: el.id || '', autocomplete: el.autocomplete || '', aria: el.getAttribute('aria-label') || ''}))};
        """)
        if isinstance(result, Mapping):
            return {
                "url": url,
                "title": clean(result.get("title"), 160),
                "body": str(result.get("body") or body)[:1800],
                "inputs": result.get("inputs") or [],
            }
    except Exception:
        pass
    return {"url": url, "title": "", "body": body, "inputs": []}


def classify_page(driver: Any) -> str:
    """Classify an auth page without treating a login password as signup."""
    snapshot = page_snapshot(driver)
    raw_url = str(getattr(driver, "current_url", "") or "").lower()
    url = raw_url.split("?", 1)[0].rstrip("/")
    body = str(snapshot.get("body") or "").lower()
    if any(value in body for value in (
        "cloudflare", "verify you are human", "unusual traffic", "security check",
        "安全验证", "人机验证", "challenge",
    )):
        return "security"
    if "chatgpt.com" in url and not any(value in url for value in (
        "/api/auth/session", "/auth/", "about-you", "/profile",
    )):
        return "home"
    if "email-verification" in url or "email-otp" in url or is_email_verification_page(driver):
        return "otp"
    if "auth.openai.com" in url and any(value in url for value in ("/log-in/password", "/login/password")):
        return "login_password"
    if "auth.openai.com" in url and ("/password" in url or "new-password" in url):
        return "signup_password"
    if any(value in url for value in ("about-you", "/profile", "create-account/about", "signup/profile")):
        return "profile"
    if "auth.openai.com" in url and any(value in url for value in ("/authorize", "/callback", "/continue")):
        return "oauth_callback"
    input_names = " ".join(
        " ".join(str(item.get(key) or "") for key in ("name", "id", "autocomplete", "aria", "type"))
        for item in snapshot.get("inputs") or [] if isinstance(item, Mapping)
    ).lower()
    if any(value in input_names or value in body for value in (
        "birthday", "birthdate", "full_name", "about you", "年龄", "生日",
    )):
        return "profile"
    if any(value in input_names for value in ("password", "new-password")) and "auth.openai.com" in url:
        return "signup_password"
    return "unknown"


def _log(log: LogFn | None, message: str, level: str = "info") -> None:
    if callable(log):
        log(message, level)


def wait_after_otp_submit(driver: Any, timeout: int, log: LogFn | None = None) -> str:
    deadline = time.monotonic() + max(3, int(timeout or 30))
    last = "unknown"
    while time.monotonic() < deadline:
        state = classify_page(driver)
        if state != last:
            last = state
            _log(log, f"OTP 提交后页面状态：{state}，位置={safe_page_location(driver)}")
        if state in {"signup_password", "login_password", "profile", "oauth_callback", "home", "security"}:
            return state
        if state == "otp":
            body = str(page_snapshot(driver).get("body") or "").lower()
            if any(value in body for value in (
                "invalid code", "incorrect code", "expired", "验证码错误", "验证码无效",
            )):
                raise FreeRegisterError(
                    "free_email_otp_validate", "验证 Free 邮箱验证码",
                    "验证码提交后页面仍显示错误，验证码可能已过期",
                    error_code="free_email_otp_invalid",
                )
        time.sleep(0.5)
    raise FreeRegisterError(
        "free_roxy_page_state", "等待 RoxyBrowser 页面状态",
        f"OTP 提交后 {max(3, int(timeout or 30))} 秒内未离开验证码页（{safe_page_location(driver)}）",
        error_code="free_roxy_post_otp_timeout",
    )


def wait_after_email_submit(driver: Any, timeout: int, log: LogFn | None = None) -> str:
    """Wait for the auth server to choose signup, existing login, or OTP."""
    deadline = time.monotonic() + max(3, int(timeout or 45))
    last = ""
    while time.monotonic() < deadline:
        state = classify_page(driver)
        if state != last:
            last = state
            _log(log, f"邮箱提交后页面状态：{state}，位置={safe_page_location(driver)}")
        if state in {
            "otp", "login_password", "signup_password", "home", "security",
            "profile", "oauth_callback",
        }:
            return state
        time.sleep(0.5)
    raise FreeRegisterError(
        "free_roxy_page_state", "等待 RoxyBrowser 页面状态",
        f"邮箱提交后页面未进入密码、验证码或首页（{safe_page_location(driver)}）",
        error_code="free_roxy_post_email_timeout",
    )


def switch_login_to_email_code(driver: Any, human: Any | None = None, log: LogFn | None = None) -> None:
    """Select the passwordless email OTP action used by the reference clients."""
    if human is not None and callable(getattr(human, "delay", None)):
        human.delay("click")
    try:
        clicked = bool(driver.execute_script(r"""
          const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
            && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none';
          const enabled = el => !el.disabled && String(el.getAttribute('aria-disabled') || '').toLowerCase() !== 'true';
          const norm = s => String(s || '').replace(/\s+/g, '').toLowerCase();
          const candidates = [...document.querySelectorAll('button,a,input[type="submit"],[role="button"],[role="link"]')]
            .filter(el => visible(el) && enabled(el));
          const hit = candidates.find(el => {
            const name = String(el.getAttribute('name') || '').toLowerCase();
            const value = String(el.getAttribute('value') || '').toLowerCase();
            const attrs = [el.id, name, value, el.getAttribute('aria-label'), el.getAttribute('title'),
              el.getAttribute('data-testid'), el.textContent].join(' ').toLowerCase();
            const text = norm(el.textContent || el.getAttribute('value') || '');
            return (name === 'intent' && value.includes('passwordless') && value.includes('otp'))
              || /passwordless.*otp|otp.*passwordless|one[-_\s]?time.*code|code.*one[-_\s]?time/.test(attrs)
              || /一次性验证码|一次性驗證碼|ワンタイムコード|メールでコード|useaone-timecode|continuewithaone-timecode|loginwithaone-timecode/.test(text);
          });
          if (!hit) return false;
          hit.scrollIntoView({block: 'center'});
          hit.click();
          return true;
        """))
    except Exception:
        clicked = False
    if not clicked:
        raise FreeRegisterError(
            "free_existing_login", "已有 Free 账号登录",
            f"登录密码页没有找到“使用邮箱验证码”入口（{safe_page_location(driver)}）",
            retryable=False,
            error_code="free_existing_passwordless_action_missing",
        )
    _log(log, f"已切换为已有账号邮箱验证码登录，位置={safe_page_location(driver)}", "success")


def wait_after_passwordless_switch(driver: Any, timeout: int, log: LogFn | None = None) -> str:
    deadline = time.monotonic() + max(3, int(timeout or 45))
    last = "login_password"
    while time.monotonic() < deadline:
        state = classify_page(driver)
        if state != last:
            last = state
            _log(log, f"已有账号登录切换后页面状态：{state}，位置={safe_page_location(driver)}")
        if state in {"otp", "home", "security", "profile", "oauth_callback", "signup_password"}:
            return state
        time.sleep(0.5)
    raise FreeRegisterError(
        "free_existing_login", "已有 Free 账号登录",
        f"切换邮箱验证码后页面未继续（当前 {safe_page_location(driver)}）",
        error_code="free_existing_login_transition_timeout",
    )


def wait_for_home(driver: Any, timeout: int, log: LogFn | None = None) -> None:
    deadline = time.monotonic() + max(3, int(timeout or 60))
    last = ""
    while time.monotonic() < deadline:
        state = classify_page(driver)
        if state != last:
            _log(log, f"等待确认 ChatGPT 首页：当前={state}，位置={safe_page_location(driver)}")
            last = state
        if state == "home":
            return
        if state == "security":
            raise FreeRegisterError(
                "free_roxy_challenge", "等待注册页安全验证",
                f"认证完成后仍停留在安全验证页（{safe_page_location(driver)}）",
                retryable=False,
                error_code="free_roxy_security_challenge",
            )
        if state == "login_password":
            raise FreeRegisterError(
                "free_roxy_login_password", "识别登录密码页",
                "邮箱验证后仍停留在登录密码页，未确认账号登录完成",
                retryable=False,
                error_code="free_roxy_login_password_page",
            )
        time.sleep(0.5)
    raise FreeRegisterError(
        "free_roxy_page_state", "确认 ChatGPT 登录首页",
        f"未确认 ChatGPT 首页（当前页面 {safe_page_location(driver)}）",
        error_code="free_roxy_home_not_confirmed",
    )


__all__ = [
    "classify_page",
    "page_snapshot",
    "switch_login_to_email_code",
    "wait_after_email_submit",
    "wait_after_otp_submit",
    "wait_after_passwordless_switch",
    "wait_for_home",
]
