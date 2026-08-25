"""RoxyBrowser signup bootstrap and credential-free email form handling."""

from __future__ import annotations

import time
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit

try:
    from .free_register_common import FreeRegisterError, clean
    from .free_roxy_auth_bootstrap import (
        submit_email_via_browser_nextauth as _submit_email_via_browser_nextauth,
    )
except ImportError:
    from free_register_common import FreeRegisterError, clean  # type: ignore[no-redef]
    from free_roxy_auth_bootstrap import (  # type: ignore[no-redef]
        submit_email_via_browser_nextauth as _submit_email_via_browser_nextauth,
    )


LOGIN_URL = "https://chatgpt.com/auth/login"
# The login?email page is a short-lived SPA transition.  Keep the recovery
# threshold separate from the final debounce so a transient blank field gets
# one early, same-form resubmission without extending the attempt forever.
EMAIL_CLEAR_DEBOUNCE_SECONDS = 18.0
EMAIL_CLEAR_RECOVERY_SECONDS = 2.0
EMAIL_BROWSER_BOOTSTRAP_SECONDS = 5.0
EMAIL_NON_LOGIN_CLEAR_DEBOUNCE_SECONDS = 5.0
EMAIL_TRANSITION_TIMEOUT_SECONDS = 20.0
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
    # Only dismiss selectors that are unambiguously cookie-consent controls.
    # Do not click generic "Continue"/"Accept" text: those can be auth or IdP
    # actions on the same page.
    try:
        driver.execute_script(r"""
          const selectors = [
            '#onetrust-accept-btn-handler',
            '[data-testid="cookie-accept"]',
            '[data-testid="accept-cookies"]'
          ];
          const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
            && getComputedStyle(el).visibility !== 'hidden'
            && getComputedStyle(el).display !== 'none'
            && !el.disabled
            && String(el.getAttribute('aria-disabled') || '').toLowerCase() !== 'true';
          for (const selector of selectors) {
            const button = document.querySelector(selector);
            if (visible(button)) { button.click(); break; }
          }
        """)
    except Exception:
        pass
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


def _submit_email_form_fallback(driver: Any, email: str, *, recovery: bool = False) -> dict[str, Any]:
    """Submit only the active email form when the asynchronous probe fails.

    The fallback deliberately resolves the form from the email input again. It
    never searches or clicks a page-global button, which keeps provider/IdP
    controls outside the registration action. A CDP Runtime evaluation is a
    last transport fallback for drivers that reject a normal script call.
    """
    fallback_script = r"""
      /* __gptphone_submit_email_form_fallback__ */
      const email = String(arguments[0] || '').trim();
      const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
        && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none'
        && !el.disabled && !el.readOnly
        && String(el.getAttribute('aria-disabled') || '').toLowerCase() !== 'true';
      const input = [...document.querySelectorAll(
        'input[type="email"],input[name="email"],input[name="username"],input[autocomplete*="email"]'
      )].find(visible);
      if (!input) return {ok:false, reason:'missing_email_input'};
      const form = input.closest('form');
      if (!form) return {ok:false, reason:'missing_email_form'};
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
      input.focus();
      if (setter) setter.call(input, email); else input.value = email;
      try { input.dispatchEvent(new InputEvent('beforeinput', {bubbles:true, cancelable:true,
        inputType:'insertText', data:email})); } catch (_) {}
      try { input.dispatchEvent(new InputEvent('input', {bubbles:true, inputType:'insertText', data:email})); }
      catch (_) { input.dispatchEvent(new Event('input', {bubbles:true})); }
      input.dispatchEvent(new Event('change', {bubbles:true}));
      input.dispatchEvent(new FocusEvent('blur', {bubbles:true}));
      input.blur(); input.focus();
      const attrText = el => {
        const own = [el.id, el.name, el.type, el.value, el.className, el.textContent,
          el.getAttribute('href'),
          el.getAttribute('formaction'), el.getAttribute('aria-label'), el.getAttribute('title'),
          el.getAttribute('data-testid'), el.getAttribute('data-test-id'),
          el.getAttribute('data-provider'), el.getAttribute('data-auth-provider'), el.getAttribute('data-idp')]
          .filter(Boolean).join(' ');
        const children = [...el.querySelectorAll('[aria-label],[title],[data-provider],[data-testid],[data-test-id],img,svg,use')]
          .map(x => [x.getAttribute('aria-label'), x.getAttribute('title'), x.getAttribute('data-provider'),
            x.getAttribute('data-testid'), x.getAttribute('data-test-id'), x.getAttribute('alt'),
            x.getAttribute('src'), x.getAttribute('href')].filter(Boolean).join(' ')).join(' ');
        return `${own} ${children}`.toLowerCase();
      };
      const bad = /google|apple|microsoft|github|facebook|saml|sso|oauth|social|oidc|idp|authorize|consent|grant|allow|sign[ -]?in with/;
      const cancel = /(^|[^a-z])(cancel|back|skip)([^a-z]|$)/;
      const candidates = [...form.querySelectorAll('button,input[type="submit"]')]
        .filter((el, index, values) => values.indexOf(el) === index)
        .filter(el => visible(el) && !bad.test(attrText(el)) && !cancel.test(attrText(el)));
      const submit = candidates.map((el, index) => {
        const text = attrText(el);
        const type = String(el.getAttribute('type') || '').toLowerCase();
        const rect = el.getBoundingClientRect();
        let score = type === 'submit' ? 100 : 0;
        if (/continue|next|create|sign[ -]?up|submit|start|email/.test(text)) score += 35;
        if (/submit|continue|next/i.test(String(el.getAttribute('data-testid') || ''))) score += 25;
        score -= Math.min(20, Math.abs(rect.top - input.getBoundingClientRect().bottom) / 100);
        return {el, index, score};
      }).sort((a, b) => b.score - a.score || a.index - b.index)[0]?.el || null;
      const trigger = () => {
        input.focus();
        let triggered = false;
        try {
          if (submit && !submit.disabled) { submit.click(); triggered = true; }
        } catch (_) {}
        if (!triggered && typeof form.requestSubmit === 'function') {
          try { form.requestSubmit(submit || undefined); triggered = true; }
          catch (_) { try { form.requestSubmit(); triggered = true; } catch (_) {} }
        }
        const probe = window.__gptphone_email_submit_probe__;
        if (probe && probe.record) probe.record.triggered = triggered;
        return triggered;
      };
      const canRequestSubmit = typeof form.requestSubmit === 'function';
      if (!submit && !canRequestSubmit) return {ok:false, reason:'no_safe_submit_control'};
      const triggered = trigger();
      return {ok:!!triggered, mode:'same_form_request_submit', fallback:true,
        recovery:!!arguments[1], submit_observed:!!(window.__gptphone_email_submit_probe__ &&
          window.__gptphone_email_submit_probe__.record && window.__gptphone_email_submit_probe__.record.submit_observed)};
    """
    try:
        result = driver.execute_script(fallback_script, email, recovery) or {}
        if isinstance(result, Mapping):
            return dict(result)
        return {"ok": False, "reason": "fallback_invalid_result"}
    except Exception as exc:
        cdp = getattr(driver, "execute_cdp_cmd", None)
        if callable(cdp):
            # The normal fallback above has already restored the native value;
            # CDP only triggers the nearest form and does not carry credentials
            # in a diagnostic string.
            try:
                result = cdp("Runtime.evaluate", {
                    "expression": """
                      (() => {
                        const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
                          && getComputedStyle(el).visibility !== 'hidden'
                          && getComputedStyle(el).display !== 'none' && !el.disabled;
                        const input = [...document.querySelectorAll(
                          'input[type=\"email\"],input[name=\"email\"],input[name=\"username\"],input[autocomplete*=\"email\"]'
                        )].find(el => visible(el) && !el.readOnly);
                        const form = input && input.closest('form');
                        if (!form) return {ok:false, reason:'missing_email_form'};
                        const text = el => [el.id,el.name,el.type,el.value,el.className,
                          el.getAttribute('aria-label'),el.getAttribute('title'),el.getAttribute('data-testid'),
                          el.getAttribute('data-provider'),el.getAttribute('data-auth-provider'),el.textContent]
                          .filter(Boolean).join(' ').toLowerCase();
                        const bad = /google|apple|microsoft|github|facebook|saml|sso|oauth|social|oidc|idp|authorize|consent|grant|allow|sign[ -]?in with/;
                        const cancel = /(^|[^a-z])(cancel|back|skip)([^a-z]|$)/;
                        const submit = [...form.querySelectorAll('button,input[type="submit"]')]
                          .filter((el, index, values) => values.indexOf(el) === index)
                          .filter(el => visible(el) && !bad.test(text(el)) && !cancel.test(text(el)))[0];
                        try {
                          if (submit && !submit.disabled) { submit.click(); return {ok:true, mode:'cdp_same_form_click', fallback:true}; }
                          if (typeof form.requestSubmit === 'function') { form.requestSubmit(); return {ok:true, mode:'cdp_request_submit', fallback:true}; }
                        } catch (_) {}
                        return {ok:false, reason:'request_submit_unavailable'};
                      })()
                    """,
                    "returnByValue": True,
                }) or {}
                value = result.get("result", {}).get("value") if isinstance(result, Mapping) else None
                if isinstance(value, Mapping):
                    return dict(value)
            except Exception as cdp_exc:
                return {"ok": False, "reason": f"{type(exc).__name__}/{type(cdp_exc).__name__}"}
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
              el.getAttribute('formaction'), el.getAttribute('aria-label'), el.getAttribute('title'),
              el.getAttribute('data-testid'), el.getAttribute('data-test-id'),
              el.getAttribute('data-provider'), el.getAttribute('data-auth-provider'), el.getAttribute('data-idp'),
              el.textContent]
              .filter(Boolean).join(' ');
            const children = [...el.querySelectorAll('[aria-label],[title],[data-provider],[data-testid],[data-test-id],img,svg,use')]
              .map(x => [x.getAttribute('aria-label'), x.getAttribute('title'), x.getAttribute('data-provider'),
                x.getAttribute('data-testid'), x.getAttribute('data-test-id'), x.getAttribute('alt'),
                x.getAttribute('src'), x.getAttribute('href')].filter(Boolean).join(' ')).join(' ');
            return `${own} ${children}`.toLowerCase();
          };
          const bad = /google|apple|microsoft|github|facebook|saml|sso|oauth|social|oidc|idp|authorize|consent|grant|allow|sign[ -]?in with/;
          const cancel = /(^|[^a-z])(cancel|back|skip)([^a-z]|$)/;
          const formId = form.getAttribute('id') || '';
          const candidates = [...form.querySelectorAll('button,input[type="submit"]'),
            ...(formId ? [...document.querySelectorAll(`button[form="${CSS.escape(formId)}"],input[type="submit"][form="${CSS.escape(formId)}"]`)] : [])]
            .filter((el, index, values) => values.indexOf(el) === index)
            .filter(el => visible(el) && !bad.test(attrText(el)) && !cancel.test(attrText(el))
              );
          const scored = candidates.map((el, index) => {
            const text = attrText(el);
            const type = String(el.getAttribute('type') || '').toLowerCase();
            const rect = el.getBoundingClientRect();
            let score = type === 'submit' ? 100 : 0;
            if (/continue|next|create|sign[ -]?up|submit|start|email/.test(text)) score += 35;
            if (el.matches('[data-testid*="submit" i],[data-testid*="continue" i],[data-testid*="next" i]')) score += 25;
            score -= Math.min(20, Math.abs(rect.top - input.getBoundingClientRect().bottom) / 100);
            return {el, index, score};
          }).sort((a, b) => b.score - a.score || a.index - b.index);
          const submit = scored.length ? scored[0].el : null;
          const oldProbe = window.__gptphone_email_submit_probe__;
          if (oldProbe && oldProbe.form && oldProbe.listener) {
            try { oldProbe.form.removeEventListener('submit', oldProbe.listener, true); } catch (_) {}
          }
          const record = {submit_observed:false, triggered:false, fallback:false,
            mode:recovery ? 'controlled_resubmit' : 'async_enter_click'};
          const listener = () => { record.submit_observed = true; record.observed_at = Date.now(); };
          form.addEventListener('submit', listener, true);
          window.__gptphone_email_submit_probe__ = {form, listener, record};
          const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
          input.focus();
          if (setter) setter.call(input, email); else input.value = email;
          try { input.dispatchEvent(new InputEvent('beforeinput', {bubbles:true, cancelable:true,
            inputType:'insertText', data:email})); } catch (_) {}
          try { input.dispatchEvent(new InputEvent('input', {bubbles:true, inputType:'insertText', data:email})); }
          catch (_) { input.dispatchEvent(new Event('input', {bubbles:true})); }
          input.dispatchEvent(new Event('change', {bubbles:true}));
          input.dispatchEvent(new FocusEvent('blur', {bubbles:true}));
          input.blur(); input.focus();
          if (submit) submit.scrollIntoView({block:'center', inline:'nearest'});
          const trigger = () => {
            try {
              input.focus();
              input.dispatchEvent(new KeyboardEvent('keydown', {bubbles:true, cancelable:true, key:'Enter', code:'Enter'}));
              input.dispatchEvent(new KeyboardEvent('keypress', {bubbles:true, cancelable:true, key:'Enter', code:'Enter'}));
              input.dispatchEvent(new KeyboardEvent('keyup', {bubbles:true, cancelable:true, key:'Enter', code:'Enter'}));
              let triggered = false;
              if (submit && !submit.disabled) { submit.click(); triggered = true; }
              if (!triggered && typeof form.requestSubmit === 'function') {
                try { form.requestSubmit(submit || undefined); triggered = true; }
                catch (_) { try { form.requestSubmit(); triggered = true; } catch (_) {} }
              }
              record.triggered = triggered;
            } catch (_) {
              if (typeof form.requestSubmit === 'function') {
                try { form.requestSubmit(); record.triggered = true; } catch (_) {}
              }
            }
          };
          setTimeout(trigger, 80);
          const canSubmit = !!submit || typeof form.requestSubmit === 'function';
          if (!canSubmit) return {ok:false, reason:'no_safe_submit_control'};
          return {ok:true, mode:record.mode, submit_candidate:!!submit,
            submit_probe_installed:true, request_submit_available:typeof form.requestSubmit === 'function'};
        """, email, recovery) or {}
        if isinstance(result, Mapping) and result.get("ok"):
            # New scripts report whether a same-form control actually exists.
            # Keep compatibility with minimal test/driver shims that only
            # return ``ok`` while rejecting an explicit no-control result.
            has_control_fields = "submit_candidate" in result or "request_submit_available" in result
            if not has_control_fields or result.get("submit_candidate") or result.get("request_submit_available"):
                return dict(result)
            primary = {"reason": "no_safe_submit_control"}
        else:
            primary = dict(result) if isinstance(result, Mapping) else {"reason": "invalid_script_result"}
    except Exception as exc:
        primary = {"reason": type(exc).__name__}

    fallback = _submit_email_form_fallback(driver, email, recovery=recovery)
    if fallback.get("ok"):
        has_control_fields = "submit_candidate" in fallback or "request_submit_available" in fallback
        if not has_control_fields or fallback.get("submit_candidate") or fallback.get("request_submit_available"):
            return fallback
        fallback = {**fallback, "ok": False, "reason": "no_safe_submit_control"}
    reason = clean(primary.get("reason"), 80) or "safe_submit_failed"
    fallback_reason = clean(fallback.get("reason"), 80)
    return {"ok": False, "reason": reason, "fallback_reason": fallback_reason}


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
          const probe = window.__gptphone_email_submit_probe__ || {};
          const record = probe.record || {};
          return {input_count:inputs.length, has_blank:values.some(value => !value),
            has_expected:values.some(value => value === expected), path:location.pathname,
            has_email_query:new URLSearchParams(location.search).has('email'),
            submit_observed:!!record.submit_observed, submit_triggered:!!record.triggered,
            submit_mode:String(record.mode || ''), submit_fallback:!!record.fallback};
        """, email) or {}
        return dict(result) if isinstance(result, Mapping) else {}
    except Exception as exc:
        return {"input_count": 0, "reason": type(exc).__name__}


def _fast_auth_state(driver: Any) -> str:
    """Classify URL-only auth transitions without waiting on the DOM.

    Roxy/Chrome can temporarily block a DOM query while React replaces the
    login form.  The URL is still available during that interval and is
    sufficient to recognize the concrete states that can end email submit.
    """
    try:
        parsed = urlsplit(str(getattr(driver, "current_url", "") or ""))
    except Exception:
        return ""
    host = (parsed.hostname or "").casefold().rstrip(".")
    path = (parsed.path or "/").casefold().rstrip("/") or "/"
    if host not in {"auth.openai.com", "chatgpt.com"} and not host.endswith(".auth.openai.com"):
        return ""
    if "/cdn-cgi/challenge-platform" in path or any(
        marker in path for marker in ("/security-challenge", "/security_check", "/captcha")
    ):
        return "security"
    if host == "auth.openai.com" or host.endswith(".auth.openai.com"):
        # API responses are transport state, not a browser page transition.
        # In particular, /api/accounts/authorize/continue must be handled by
        # the page classifier after the response is observed.
        if path.startswith("/api/"):
            return ""
        if path in {"/email-verification", "/email-otp"} or path.startswith(("/email-verification/", "/email-otp/")):
            return "otp"
        if path in {"/log-in/password", "/login/password"}:
            return "login_password"
        if "/password" in path or path.endswith("/new-password"):
            return "signup_password"
        if any(marker in path for marker in ("/about-you", "/about_you", "/birthdate", "/create-account/profile", "/signup/profile")):
            return "profile"
        if any(marker in path for marker in ("/authorize", "/callback", "/continue")):
            return "oauth_callback"
        return ""
    # Do not call the ChatGPT home page a successful transition while the
    # login form is still mounted under /auth/login.
    if path == "/" or (not path.startswith("/auth/") and "/api/" not in path):
        return "home"
    return ""


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
    select_auth_window: Callable[..., Any] | None = None,
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
    last_reason = "email_form_not_ready"
    max_attempts = max(1, min(3, int(attempts or EMAIL_SUBMIT_ATTEMPTS)))
    browser_bootstrap_attempted = False

    for attempt in range(1, max_attempts + 1):
        # Recovery is scoped to this submit attempt.  A failed first attempt
        # must not consume the one recovery allowed for the next refill.
        recovery_done = False
        fill_deadline = time.monotonic() + min(20, max(5, int(timeout or 20)))
        clicked_entry = False
        while time.monotonic() < fill_deadline:
            if callable(select_auth_window):
                try:
                    select_auth_window(driver, log)
                except TypeError:
                    try:
                        select_auth_window(driver)
                    except Exception:
                        pass
                except Exception:
                    pass
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

        # Selenium's page/script timeout (often 90s) must not turn this SPA
        # transition into a 45s wait.  AutoRegister observes the same form for
        # roughly twenty seconds before starting the next attempt.
        wait_deadline = time.monotonic() + EMAIL_TRANSITION_TIMEOUT_SECONDS
        cleared_at: float | None = None
        recovery_attempts = 0
        last_recovery_at: float | None = None
        recovery_finished_at: float | None = None
        last_classified_at = 0.0
        while time.monotonic() < wait_deadline:
            if callable(select_auth_window):
                try:
                    select_auth_window(driver, log)
                except TypeError:
                    try:
                        select_auth_window(driver)
                    except Exception:
                        pass
                except Exception:
                    pass
            # Read the URL and the lightweight email form probe before the
            # full page snapshot.  The latter can block during a React
            # unmount, which used to consume the whole recovery window.
            state = _fast_auth_state(driver)
            if state == "security":
                state = wait_security(driver, min(60, int(timeout or 60)), log)
            if state in valid_states:
                return state
            form_state = _email_form_state(driver, expected)
            input_count = int(form_state.get("input_count") or 0)
            login_email_transition = (
                str(form_state.get("path") or "").rstrip("/").casefold() == "/auth/login"
                and bool(form_state.get("has_email_query"))
            )
            # React can unmount the email input while the login?email SPA
            # transition is in flight.  The URL/query is the stable signal;
            # requiring input_count > 0 here used to skip the only recovery
            # opportunity for exactly that state.
            email_value_cleared = (
                input_count > 0
                and bool(form_state.get("has_blank"))
                and not bool(form_state.get("has_expected"))
            )
            blank_transition = email_value_cleared or (
                login_email_transition and input_count == 0
            )
            if blank_transition:
                now = time.monotonic()
                if cleared_at is None:
                    cleared_at = now
                    _log(
                        log,
                        f"邮箱提交后输入框进入清空态（attempt={attempt}，path={clean(form_state.get('path'), 80) or '-'}，"
                        f"email_query={bool(form_state.get('has_email_query'))}，inputs={input_count}，"
                        f"has_blank=True，has_expected=False）",
                    )
                elapsed = now - cleared_at
                debounce = (
                    EMAIL_CLEAR_DEBOUNCE_SECONDS
                    if login_email_transition
                    else EMAIL_NON_LOGIN_CLEAR_DEBOUNCE_SECONDS
                )
                can_retry_recovery = (
                    login_email_transition
                    and not recovery_done
                    and recovery_attempts < 3
                    and elapsed >= EMAIL_CLEAR_RECOVERY_SECONDS
                    and (
                        last_recovery_at is None
                        or now - last_recovery_at >= 0.8
                    )
                )
                if can_retry_recovery:
                    recovered = _submit_email_form(driver, expected, recovery=True)
                    recovery_attempts += 1
                    last_recovery_at = now
                    reason = clean(recovered.get("reason"), 80)
                    # If React has not mounted the form yet, leave the
                    # recovery window open for two short re-location attempts.
                    # A successful submission (or any non-mount failure)
                    # consumes the one logical recovery.
                    if recovered.get("ok") or reason not in {
                        "missing_email_input",
                        "missing_email_form",
                    } or recovery_attempts >= 3:
                        recovery_done = True
                    if recovered.get("ok"):
                        recovery_finished_at = now
                    _log(
                        log,
                        (
                            "login?email 清空态达到恢复阈值，执行同表单受控补交"
                            if recovered.get("ok")
                            else (
                                "login?email 清空态等待邮箱表单重新挂载，"
                                f"第 {recovery_attempts}/3 次定位未完成："
                                f"{reason or '未返回原因'}"
                            )
                        ),
                        "info" if recovered.get("ok") else "warn",
                    )
                if (
                    login_email_transition
                    and recovery_done
                    and not browser_bootstrap_attempted
                    and elapsed >= EMAIL_BROWSER_BOOTSTRAP_SECONDS
                ):
                    browser_bootstrap_attempted = True
                    browser_bootstrap = _submit_email_via_browser_nextauth(
                        driver, expected, timeout,
                    )
                    stage = clean(browser_bootstrap.get("stage"), 24) or "transport"
                    status = browser_bootstrap.get("status")
                    reason = clean(browser_bootstrap.get("reason"), 48)
                    _log(
                        log,
                        "login?email 同表单补交后仍未跳转，执行一次浏览器内认证启动"
                        f"（stage={stage}，HTTP={status if status is not None else '-'}，"
                        f"result={'accepted' if browser_bootstrap.get('ok') else 'rejected'}"
                        f"{f'，reason={reason}' if reason else ''}）",
                        "info" if browser_bootstrap.get("ok") else "warn",
                    )
                # Do not reset cleared_at or extend wait_deadline after
                # recovery.  The original blank transition still expires at
                # the fixed 18s/5s debounce, matching AutoRegister.
                if elapsed >= debounce:
                    last_reason = "login_email_cleared" if login_email_transition else "email_cleared"
                    break
                # A successful recovery may have mounted the OTP page without
                # changing the URL immediately.  Give the normal classifier a
                # bounded opportunity after the async form action, but never
                # let it run before the blank-state recovery is attempted.
                if (
                    recovery_done
                    and recovery_finished_at is not None
                    and now - recovery_finished_at >= 0.5
                    and now - last_classified_at >= 1.0
                ):
                    last_classified_at = now
                    state = classify(driver)
                    if state == "security":
                        state = wait_security(driver, min(60, int(timeout or 60)), log)
                    if state in valid_states:
                        return state
                time.sleep(0.5)
                continue
            else:
                cleared_at = None
            now = time.monotonic()
            if now - last_classified_at >= 0.75:
                last_classified_at = now
                state = classify(driver)
                if state == "security":
                    state = wait_security(driver, min(60, int(timeout or 60)), log)
                if state in valid_states:
                    return state
            if form_state.get("submit_observed") or form_state.get("submit_triggered"):
                _log(
                    log,
                    "邮箱提交探针状态："
                    f"attempt={attempt}，recovery={recovery_done}，elapsed={time.monotonic() - (wait_deadline - EMAIL_TRANSITION_TIMEOUT_SECONDS):.1f}s，"
                    f"submit_observed={bool(form_state.get('submit_observed'))}，"
                    f"submit_triggered={bool(form_state.get('submit_triggered'))}，"
                    f"fallback={bool(form_state.get('submit_fallback'))}",
                )
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
    "EMAIL_BROWSER_BOOTSTRAP_SECONDS", "EMAIL_CLEAR_DEBOUNCE_SECONDS", "EMAIL_CLEAR_RECOVERY_SECONDS",
    "EMAIL_NON_LOGIN_CLEAR_DEBOUNCE_SECONDS", "EMAIL_TRANSITION_TIMEOUT_SECONDS",
    "EMAIL_SUBMIT_ATTEMPTS", "LOGIN_URL",
    "is_email_verification_page", "open_signup_page", "safe_page_location",
    "submit_email_and_wait", "warmup_login_page",
]
