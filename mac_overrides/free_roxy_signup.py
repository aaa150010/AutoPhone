"""RoxyBrowser signup bootstrap and credential-free email form handling."""

from __future__ import annotations

import time
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit

try:
    from .free_register_common import FreeRegisterError, clean
except ImportError:
    from free_register_common import FreeRegisterError, clean  # type: ignore[no-redef]


LOGIN_URL = "https://chatgpt.com/auth/login"
EMAIL_CLEAR_DEBOUNCE_SECONDS = 18.0
EMAIL_SUBMIT_ATTEMPTS = 3


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


def open_signup_page(driver: Any, _email: str, timeout: int) -> None:
    """Open the normal ChatGPT login UI without a legacy NextAuth bootstrap."""
    driver.set_page_load_timeout(timeout)
    last_error: BaseException | None = None
    for attempt in range(1, 3):
        try:
            driver.get(LOGIN_URL)
        except Exception as exc:
            last_error = exc
            if _is_trusted_auth_page(driver):
                return
            if attempt < 2:
                time.sleep(0.5)
                continue
        if _is_trusted_auth_page(driver):
            return
        if attempt < 2:
            time.sleep(0.5)
    error_type = type(last_error).__name__ if last_error is not None else "UnexpectedPage"
    raise FreeRegisterError(
        "free_roxy_signup_bootstrap", "打开 RoxyBrowser 注册页",
        f"登录页导航失败（{error_type}，{safe_page_location(driver)}）",
        error_code=(
            "free_roxy_signup_navigation_timeout"
            if error_type == "TimeoutException" else "free_roxy_signup_navigation_failed"
        ),
    ) from last_error


def warmup_login_page(driver: Any, human: Any | None = None) -> None:
    """Perform a small in-profile warmup without activating a macOS window."""
    if human is not None and callable(getattr(human, "delay", None)):
        human.delay("page_warmup")
    if human is not None and not bool(getattr(human, "actions", True)):
        return
    try:
        driver.execute_cdp_cmd("Input.dispatchMouseEvent", {
            "type": "mouseMoved", "x": 180, "y": 140,
        })
    except Exception:
        pass


def _email_target(driver: Any) -> dict[str, Any]:
    try:
        result = driver.execute_script(r"""
          /* __gptphone_find_email_target__ */
          const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
            && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none'
            && !el.disabled && String(el.getAttribute('aria-disabled') || '').toLowerCase() !== 'true';
          const editable = el => visible(el) && !el.readOnly;
          const inputs = [...document.querySelectorAll(
            'input[type="email"],input[name="email"],input[name="username"],input[autocomplete*="email"]'
          )].filter(editable);
          if (inputs.length) return {ok:true, input:inputs[0], input_count:inputs.length};
          const attrs = el => [el.id, el.name, el.value, el.className, el.getAttribute('href'),
            el.getAttribute('aria-label'), el.getAttribute('title'), el.getAttribute('data-testid'),
            el.getAttribute('data-provider'), el.getAttribute('data-auth-provider'), el.textContent]
            .filter(Boolean).join(' ').toLowerCase();
          const bad = /google|apple|microsoft|github|facebook|saml|sso|oauth|social|oidc|idp|provider/;
          const good = /(^|[^a-z])(email|mail|username|passwordless|otp|magic)([^a-z]|$)/;
          const entries = [...document.querySelectorAll('button,a,[role="button"],input[type="button"],input[type="submit"]')]
            .filter(visible).filter(el => good.test(attrs(el)) && !bad.test(attrs(el)));
          return entries.length === 1
            ? {ok:false, reason:'email_entry', entry:entries[0]}
            : {ok:false, reason:entries.length ? 'ambiguous_email_entry' : 'missing_email_input', entry_count:entries.length};
        """) or {}
        return dict(result) if isinstance(result, Mapping) else {}
    except Exception as exc:
        return {"ok": False, "reason": type(exc).__name__}


def _stabilize_email(driver: Any, email: str) -> dict[str, Any]:
    try:
        result = driver.execute_script(r"""
          /* __gptphone_stabilize_email__ */
          const email = String(arguments[0] || '').trim();
          const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
            && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none'
            && !el.disabled && !el.readOnly;
          const input = [...document.querySelectorAll(
            'input[type="email"],input[name="email"],input[name="username"],input[autocomplete*="email"]'
          )].find(visible);
          if (!input) return {ok:false, reason:'missing_email_input'};
          const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
          input.scrollIntoView({block:'center', inline:'nearest'});
          input.focus();
          if (setter) setter.call(input, email); else input.value = email;
          try { input.dispatchEvent(new InputEvent('beforeinput', {bubbles:true, cancelable:true, inputType:'insertText', data:email})); } catch (_) {}
          try { input.dispatchEvent(new InputEvent('input', {bubbles:true, inputType:'insertText', data:email})); } catch (_) {
            input.dispatchEvent(new Event('input', {bubbles:true}));
          }
          input.dispatchEvent(new Event('change', {bubbles:true}));
          input.dispatchEvent(new FocusEvent('blur', {bubbles:true}));
          input.blur(); input.focus();
          const form = input.closest('form');
          return {ok:input.value.trim().toLowerCase() === email.toLowerCase(), has_form:!!form};
        """, email) or {}
        return dict(result) if isinstance(result, Mapping) else {}
    except Exception as exc:
        return {"ok": False, "reason": type(exc).__name__}


def _submit_email_form(driver: Any, email: str, *, recovery: bool = False) -> dict[str, Any]:
    """Use the input's own form and asynchronously dispatch Enter plus click."""
    try:
        result = driver.execute_script(r"""
          /* __gptphone_submit_email_form__ */
          const email = String(arguments[0] || '').trim();
          const recovery = !!arguments[1];
          const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
            && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none'
            && !el.disabled && String(el.getAttribute('aria-disabled') || '').toLowerCase() !== 'true';
          const input = [...document.querySelectorAll(
            'input[type="email"],input[name="email"],input[name="username"],input[autocomplete*="email"]'
          )].find(el => visible(el) && !el.readOnly);
          if (!input) return {ok:false, reason:'missing_email_input'};
          const form = input.closest('form');
          if (!form) return {ok:false, reason:'missing_email_form'};
          const attrText = el => {
            const own = [el.id, el.name, el.type, el.value, el.className, el.getAttribute('href'),
              el.getAttribute('formaction'), el.getAttribute('aria-label'), el.getAttribute('data-testid'),
              el.getAttribute('data-provider'), el.getAttribute('data-auth-provider'), el.getAttribute('data-idp')]
              .filter(Boolean).join(' ');
            const children = [...el.querySelectorAll('[aria-label],[data-provider],[data-testid],img,svg,use')]
              .map(x => [x.getAttribute('aria-label'), x.getAttribute('data-provider'), x.getAttribute('data-testid'),
                x.getAttribute('alt'), x.getAttribute('src'), x.getAttribute('href')].filter(Boolean).join(' ')).join(' ');
            return `${own} ${children}`.toLowerCase();
          };
          const bad = /google|apple|microsoft|github|facebook|saml|sso|oauth|social|oidc|idp|provider|authorize|consent|grant|allow/;
          const inputRect = input.getBoundingClientRect();
          const formId = form.getAttribute('id') || '';
          const buttons = [...form.querySelectorAll('button,input[type="submit"]'),
            ...(formId ? [...document.querySelectorAll(`button[form="${CSS.escape(formId)}"],input[type="submit"][form="${CSS.escape(formId)}"]`)] : [])]
            .filter((el, index, values) => values.indexOf(el) === index && visible(el)
              && !bad.test(attrText(el)) && !el.querySelector('img,svg,use'))
            .map((el, index) => { const rect = el.getBoundingClientRect(); return {el, index,
              type:String(el.getAttribute('type') || '').toLowerCase(), below:rect.top >= inputRect.bottom - 10,
              distance:Math.max(0, rect.top - inputRect.bottom)}; })
            .filter(item => item.below)
            .sort((a,b) => (b.type === 'submit') - (a.type === 'submit') || a.distance - b.distance || a.index - b.index);
          const submit = buttons.length ? buttons[0].el : null;
          if (!submit) return {ok:false, reason:'missing_safe_submit'};
          const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
          input.focus();
          if (setter) setter.call(input, email); else input.value = email;
          try { input.dispatchEvent(new InputEvent('input', {bubbles:true, inputType:'insertText', data:email})); } catch (_) {
            input.dispatchEvent(new Event('input', {bubbles:true}));
          }
          input.dispatchEvent(new Event('change', {bubbles:true}));
          input.dispatchEvent(new FocusEvent('blur', {bubbles:true}));
          input.blur(); input.focus();
          submit.scrollIntoView({block:'center', inline:'nearest'});
          setTimeout(() => {
            try {
              input.dispatchEvent(new KeyboardEvent('keydown', {bubbles:true, cancelable:true, key:'Enter', code:'Enter'}));
              input.dispatchEvent(new KeyboardEvent('keypress', {bubbles:true, cancelable:true, key:'Enter', code:'Enter'}));
              input.dispatchEvent(new KeyboardEvent('keyup', {bubbles:true, cancelable:true, key:'Enter', code:'Enter'}));
              if (!submit.disabled) submit.click();
              else if (typeof form.requestSubmit === 'function') form.requestSubmit();
            } catch (_) {}
          }, 80);
          return {ok:true, mode:recovery ? 'controlled_resubmit' : 'async_enter_click'};
        """, email, recovery) or {}
        return dict(result) if isinstance(result, Mapping) else {}
    except Exception as exc:
        return {"ok": False, "reason": type(exc).__name__}


def _email_form_state(driver: Any, email: str) -> dict[str, Any]:
    try:
        result = driver.execute_script(r"""
          /* __gptphone_email_form_state__ */
          const expected = String(arguments[0] || '').trim().toLowerCase();
          const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
            && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none'
            && !el.disabled && !el.readOnly;
          const inputs = [...document.querySelectorAll(
            'input[type="email"],input[name="email"],input[name="username"],input[autocomplete*="email"]'
          )].filter(visible);
          const values = inputs.map(el => String(el.value || '').trim().toLowerCase());
          return {input_count:inputs.length, has_blank:values.some(value => !value),
            has_expected:values.some(value => value === expected), path:location.pathname,
            has_email_query:new URLSearchParams(location.search).has('email')};
        """, email) or {}
        return dict(result) if isinstance(result, Mapping) else {}
    except Exception as exc:
        return {"input_count": 0, "reason": type(exc).__name__}


def _log(log: Callable[[str, str], None] | None, message: str, level: str = "info") -> None:
    if callable(log):
        log(message, level)


def submit_email_and_wait(
    driver: Any,
    email: str,
    human: Any,
    log: Callable[[str, str], None] | None,
    timeout: int,
    *,
    classify: Callable[[Any], str],
    wait_security: Callable[[Any, int, Callable[[str, str], None] | None], str],
    type_element: Callable[[Any, str, Any], None],
    click_element: Callable[[Any, Any, Any], None],
    attempts: int = EMAIL_SUBMIT_ATTEMPTS,
) -> str:
    """Submit one email form safely and confirm the next concrete auth state."""
    expected = str(email or "").strip()
    if "@" not in expected:
        raise FreeRegisterError(
            "free_roxy_signup_email", "填写 Free 注册邮箱", "注册邮箱格式无效",
            retryable=False, error_code="free_roxy_signup_email_invalid",
        )
    valid_states = {"otp", "login_password", "signup_password", "home", "security", "profile", "oauth_callback"}
    controlled_resubmit_used = False
    last_reason = "email_form_not_ready"
    max_attempts = max(1, min(3, int(attempts or EMAIL_SUBMIT_ATTEMPTS)))

    for attempt in range(1, max_attempts + 1):
        fill_deadline = time.monotonic() + min(20, max(5, int(timeout or 20)))
        clicked_entry = False
        while time.monotonic() < fill_deadline:
            state = classify(driver)
            if state == "security":
                state = wait_security(driver, min(60, int(timeout or 60)), log)
            if state in valid_states:
                return state
            target = _email_target(driver)
            field = target.get("input")
            if target.get("ok") and field is not None:
                type_element(field, expected, human)
                stabilized = _stabilize_email(driver, expected)
                if stabilized.get("ok") and stabilized.get("has_form"):
                    break
                last_reason = clean(stabilized.get("reason"), 80) or "email_value_not_stable"
            elif target.get("reason") == "email_entry" and target.get("entry") is not None and not clicked_entry:
                click_element(driver, target.get("entry"), human)
                clicked_entry = True
            else:
                last_reason = clean(target.get("reason"), 80) or "missing_email_input"
            time.sleep(0.4)
        else:
            if attempt < max_attempts:
                _log(log, f"第 {attempt}/{max_attempts} 次未找到稳定邮箱表单，保持同一 Profile/代理重试", "warn")
                continue
            break

        if human is not None and callable(getattr(human, "delay", None)):
            human.delay("form")
        submitted = _submit_email_form(driver, expected)
        if not submitted.get("ok"):
            last_reason = clean(submitted.get("reason"), 80) or "safe_submit_failed"
            _log(log, f"第 {attempt}/{max_attempts} 次安全邮箱表单未提交（{last_reason}）", "warn")
            continue
        _log(log, f"邮箱表单已安全提交，等待认证页选择下一步（第 {attempt}/{max_attempts} 次）")

        wait_deadline = time.monotonic() + max(24, min(45, int(timeout or 45)))
        cleared_at: float | None = None
        while time.monotonic() < wait_deadline:
            state = classify(driver)
            if state == "security":
                state = wait_security(driver, min(60, int(timeout or 60)), log)
            if state in valid_states:
                return state
            form_state = _email_form_state(driver, expected)
            input_count = int(form_state.get("input_count") or 0)
            blank_transition = input_count > 0 and bool(form_state.get("has_blank")) and not bool(form_state.get("has_expected"))
            login_email_transition = (
                str(form_state.get("path") or "").rstrip("/").casefold() == "/auth/login"
                and bool(form_state.get("has_email_query"))
            )
            if blank_transition:
                now = time.monotonic()
                if cleared_at is None:
                    cleared_at = now
                    _log(log, f"邮箱提交后输入框进入短暂清空态，最多去抖 {int(EMAIL_CLEAR_DEBOUNCE_SECONDS)} 秒")
                elapsed = now - cleared_at
                if login_email_transition and elapsed >= EMAIL_CLEAR_DEBOUNCE_SECONDS:
                    if not controlled_resubmit_used:
                        recovered = _submit_email_form(driver, expected, recovery=True)
                        controlled_resubmit_used = True
                        _log(
                            log,
                            "login?email 中间态完成去抖并执行一次受控原生补交"
                            if recovered.get("ok") else f"login?email 受控补交未生效（{clean(recovered.get('reason'), 80) or 'unknown'}）",
                            "info" if recovered.get("ok") else "warn",
                        )
                        # Give the same submission a full observation window;
                        # the recovery must not immediately fall into a refill.
                        cleared_at = now
                        wait_deadline = max(
                            wait_deadline,
                            now + EMAIL_CLEAR_DEBOUNCE_SECONDS + 0.5,
                        )
                    else:
                        last_reason = "login_email_cleared"
                        break
                elif elapsed >= EMAIL_CLEAR_DEBOUNCE_SECONDS:
                    last_reason = "email_cleared"
                    break
            else:
                cleared_at = None
            time.sleep(0.5)
        else:
            last_reason = "email_submit_transition_timeout"
        if attempt < max_attempts:
            _log(log, f"邮箱提交后仍未进入下一步，保持同一 Profile/代理重填（第 {attempt + 1}/{max_attempts} 次）", "warn")

    raise FreeRegisterError(
        "free_roxy_signup_email_submit", "提交 Free 注册邮箱",
        f"邮箱提交 {max_attempts} 次后仍未进入密码或验证码页（{last_reason}，{safe_page_location(driver)}）",
        error_code="free_roxy_signup_email_transition_failed",
    )


__all__ = [
    "EMAIL_CLEAR_DEBOUNCE_SECONDS", "EMAIL_SUBMIT_ATTEMPTS", "LOGIN_URL",
    "is_email_verification_page", "open_signup_page", "safe_page_location",
    "submit_email_and_wait", "warmup_login_page",
]
