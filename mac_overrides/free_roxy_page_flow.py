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
              id: el.id || '', autocomplete: el.autocomplete || '', aria: el.getAttribute('aria-label') || '',
              placeholder: el.getAttribute('placeholder') || '', inputmode: el.getAttribute('inputmode') || '',
              maxlength: el.getAttribute('maxlength') || '', aria_invalid: el.getAttribute('aria-invalid') || '',
              data_testid: el.getAttribute('data-testid') || el.getAttribute('data-test-id') || ''}))};
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
    input_names = " ".join(
        " ".join(str(item.get(key) or "") for key in ("name", "id", "autocomplete", "aria", "placeholder", "inputmode", "type", "maxlength"))
        for item in snapshot.get("inputs") or [] if isinstance(item, Mapping)
    ).lower()
    otp_markers = (
        "one-time", "one_time", "otp", "verification code", "verify code", "auth code",
        "inputmode numeric", "inputmode tel", "認証コード", "認証用コード", "验证码",
    )
    if any(value in input_names or value in body for value in otp_markers):
        if not any(value in input_names for value in ("password", "new-password")):
            return "otp"
    if "auth.openai.com" in url and any(value in url for value in ("/authorize", "/callback", "/continue")):
        return "oauth_callback"
    if any(value in input_names or value in body for value in (
        "birthday", "birthdate", "full_name", "about you", "年龄", "生日",
    )):
        return "profile"
    if any(value in input_names for value in ("password", "new-password")) and "auth.openai.com" in url:
        return "signup_password"
    return "unknown"


def _password_error(driver: Any) -> str:
    """Return a credential-free password form error summary, if visible."""
    try:
        result = driver.execute_script(r"""
          const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
            && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none';
          const values = [...document.querySelectorAll(
            '.react-aria-FieldError,[slot="errorMessage"],[id$="-error"],[role="alert"],[class*="error"]'
          )].filter(visible).map(el => String(el.innerText || el.textContent || '')
            .replace(/\s+/g, ' ').trim()).filter(Boolean);
          return values.slice(0, 3).join('；').slice(0, 240);
        """)
        return clean(result, 240)
    except Exception:
        return ""


def password_form_targets(driver: Any) -> tuple[Any, Any]:
    """Resolve the visible signup password field and its nearest form submit."""
    if classify_page(driver) != "signup_password":
        raise FreeRegisterError(
            "free_roxy_signup_password", "提交 Free 注册密码",
            f"当前页面不是注册密码页（{safe_page_location(driver)}）",
            error_code="free_roxy_signup_password_wrong_page",
        )
    try:
        result = driver.execute_script(r"""
          const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
            && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none'
            && !el.disabled && !el.readOnly;
          const input = [...document.querySelectorAll(
            'input[type="password"],input[name*="password" i],input[autocomplete="new-password"]'
          )].find(visible);
          if (!input) return {ok:false, reason:'missing_password_input'};
          const form = input.closest('form');
          const scope = form || document;
          const ir = input.getBoundingClientRect();
          const candidates = [...scope.querySelectorAll('button,input[type="submit"]')]
            .filter(el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length));
          const buttons = candidates
            .filter(el => !el.disabled && String(el.getAttribute('aria-disabled') || '').toLowerCase() !== 'true')
            .map((el, index) => {
              const r = el.getBoundingClientRect();
              return {el, index, below: r.top >= ir.bottom - 10,
                distance: Math.max(0, r.top - ir.bottom) + Math.abs((r.left + r.right - ir.left - ir.right) / 2) / 10};
            }).filter(item => item.below).sort((a, b) => a.distance - b.distance || a.index - b.index);
          if (!buttons.length) return {ok:false, reason:candidates.length ? 'submit_disabled' : 'missing_form_submit'};
          const selected = buttons[0].el;
          return {ok:true, input, button:selected, button_type:String(selected.type || 'button'), form_valid:form ? form.checkValidity() : true};
        """) or {}
    except FreeRegisterError:
        raise
    except Exception as exc:
        raise FreeRegisterError(
            "free_roxy_signup_password", "提交 Free 注册密码",
            f"读取注册密码表单失败（{type(exc).__name__}，{safe_page_location(driver)}）",
            error_code="free_roxy_signup_password_form_failed",
        ) from exc
    if not isinstance(result, Mapping) or not result.get("ok"):
        reason = clean(result.get("reason"), 80) if isinstance(result, Mapping) else "invalid_result"
        raise FreeRegisterError(
            "free_roxy_signup_password", "提交 Free 注册密码",
            f"注册密码表单不完整（{reason or 'unknown'}，{safe_page_location(driver)}）",
            error_code="free_roxy_signup_password_form_incomplete",
    )
    return result.get("input"), result.get("button")


def install_password_submit_probe(driver: Any, field: Any, button: Any) -> dict[str, Any]:
    """Install a one-shot, page-local submit observer without capturing secrets."""
    try:
        result = driver.execute_script(r"""
          const input = arguments[0], button = arguments[1];
          const form = input && input.closest ? input.closest('form') : null;
          const key = '__gptphone_password_submit_probe__';
          const record = {submit_observed:false, invalid:false, button_type:String(button && button.type || 'button'),
            button_disabled:!!(button && button.disabled), aria_disabled:String(button && button.getAttribute('aria-disabled') || '')};
          if (form) {
            record.invalid = !form.checkValidity();
            form.addEventListener('submit', event => { record.submit_observed = true; record.invalid = !form.checkValidity(); }, {capture:true, once:false});
          }
          window[key] = {record, form};
          return record;
        """, field, button) or {}
        return dict(result) if isinstance(result, Mapping) else {}
    except Exception:
        return {}


def read_password_submit_probe(driver: Any) -> dict[str, Any]:
    try:
        result = driver.execute_script(r"""
          const item = window.__gptphone_password_submit_probe__ || {};
          const record = item.record || {};
          return {submit_observed:!!record.submit_observed, invalid:!!record.invalid,
            button_type:String(record.button_type || 'button'), button_disabled:!!record.button_disabled,
            aria_disabled:String(record.aria_disabled || '')};
        """) or {}
        return dict(result) if isinstance(result, Mapping) else {}
    except Exception:
        return {}


def native_password_submit(driver: Any, field: Any, button: Any) -> bool:
    try:
        result = driver.execute_script(r"""
          const input = arguments[0], submitter = arguments[1];
          const form = input && input.closest ? input.closest('form') : null;
          if (!form) return false;
          if (typeof form.requestSubmit === 'function') form.requestSubmit(submitter || undefined);
          else HTMLFormElement.prototype.submit.call(form);
          return true;
        """, field, button)
        return bool(result)
    except Exception:
        return False


def wait_after_signup_password_submit(
    driver: Any,
    timeout: int,
    log: LogFn | None = None,
) -> str:
    """Require a real transition after one password submission."""
    deadline = time.monotonic() + max(3, int(timeout or 45))
    while time.monotonic() < deadline:
        state = classify_page(driver)
        if state != "signup_password":
            _log(log, f"注册密码提交后页面状态：{state}，位置={safe_page_location(driver)}")
            if state in {"otp", "profile", "oauth_callback", "home", "security", "login_password"}:
                return state
        error = _password_error(driver)
        if error:
            raise FreeRegisterError(
                "free_roxy_signup_password", "提交 Free 注册密码",
                f"注册密码被页面拒绝：{error}",
                error_code="free_roxy_signup_password_rejected",
                retryable=False,
            )
        time.sleep(0.5)
    raise FreeRegisterError(
        "free_roxy_signup_password", "提交 Free 注册密码",
        f"密码提交后页面没有继续，已停止重复提交（{safe_page_location(driver)}）",
        error_code="free_roxy_signup_password_transition_timeout",
    )


def click_resend_email_otp(driver: Any, human: Any | None = None) -> None:
    """Click one visible resend action without relying on a single locale."""
    if classify_page(driver) != "otp":
        raise FreeRegisterError(
            "free_email_otp_wait", "等待 Free 邮箱验证码",
            f"当前页面已不是邮箱验证码页，不能重新发送（{safe_page_location(driver)}）",
            error_code="free_email_otp_resend_wrong_page",
        )
    if human is not None and callable(getattr(human, "delay", None)):
        human.delay("click")
    try:
        clicked = bool(driver.execute_script(r"""
          const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
            && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none';
          const enabled = el => !el.disabled && String(el.getAttribute('aria-disabled') || '').toLowerCase() !== 'true';
          const candidates = [...document.querySelectorAll(
            'button,a,[role="button"],[role="link"],input[type="button"],input[type="submit"]'
          )].filter(el => visible(el) && enabled(el));
          const hit = candidates.find(el => {
            const name = String(el.getAttribute('name') || '').toLowerCase();
            const value = String(el.getAttribute('value') || '').toLowerCase();
            const attrs = [el.id, name, value, el.getAttribute('data-dd-action-name'),
              el.getAttribute('aria-label'), el.getAttribute('title'), el.getAttribute('data-testid')]
              .join(' ').toLowerCase();
            const text = String(el.innerText || el.textContent || el.getAttribute('value') || '').toLowerCase();
            return (name === 'intent' && value === 'resend')
              || /resend|send.*new|new.*code|send.*again/.test(attrs)
              || /resend|send\s+(?:a\s+)?new\s+code|send\s+again|重新发送|重发|再次发送|再送信|新しい/.test(text);
          });
          if (!hit) return false;
          hit.scrollIntoView({block:'center'}); hit.click(); return true;
        """))
    except Exception as exc:
        raise FreeRegisterError(
            "free_email_otp_wait", "等待 Free 邮箱验证码",
            f"重新发送验证码操作失败（{type(exc).__name__}）",
            error_code="free_email_otp_resend_failed",
        ) from exc
    if not clicked:
        raise FreeRegisterError(
            "free_email_otp_wait", "等待 Free 邮箱验证码",
            "验证码页没有找到可用的重新发送入口",
            error_code="free_email_otp_resend_action_missing",
        )


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
    "click_resend_email_otp",
    "classify_page",
    "page_snapshot",
    "password_form_targets",
    "install_password_submit_probe",
    "read_password_submit_probe",
    "native_password_submit",
    "switch_login_to_email_code",
    "wait_after_email_submit",
    "wait_after_otp_submit",
    "wait_after_passwordless_switch",
    "wait_after_signup_password_submit",
    "wait_for_home",
]
