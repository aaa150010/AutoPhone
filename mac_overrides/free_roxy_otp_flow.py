"""Robust, credential-safe OTP page handling for the Free Roxy flow.

The auth page can render the verification form asynchronously and has used both
single and six-cell inputs over time.  This module keeps DOM discovery,
submission telemetry and post-submit classification together so the runner
does not mistake a page-rendering problem for a mailbox problem.
"""

from __future__ import annotations

import re
import time
from typing import Any, Callable, Mapping
from urllib.parse import urljoin, urlsplit

try:
    from .free_register_common import FreeRegisterError, clean
    from .free_roxy_page_flow import classify_page, is_trusted_site_url, page_snapshot, wait_for_security_clear
    from .free_roxy_signup import safe_page_location
except ImportError:
    from free_register_common import FreeRegisterError, clean  # type: ignore[no-redef]
    from free_roxy_page_flow import classify_page, is_trusted_site_url, page_snapshot, wait_for_security_clear  # type: ignore[no-redef]
    from free_roxy_signup import safe_page_location  # type: ignore[no-redef]


LogFn = Callable[[str, str], None]
OtpWaitFn = Callable[[int], str]
OtpSubmitFn = Callable[[str, int], str]
OtpRestartFn = Callable[[int], str]

_OTP_ATTR_RE = re.compile(
    r"(?:one[-_ ]?time|otp|verification|verify|auth(?:entication)?|security|passcode|code|pin|验证码|認証|検証|コード)",
    re.IGNORECASE,
)
_NUMERIC_RE = re.compile(r"(?:numeric|decimal|tel|number|digit)", re.IGNORECASE)
_ERROR_RE = re.compile(
    r"(?:invalid|incorrect|wrong|expired|doesn't match|not valid|验证码错误|验证码无效|验证码已过期|验证码不正确|コードが正しく|無効|期限切れ|認証コード.*違|認証に失敗)",
    re.IGNORECASE,
)


def _log(log: LogFn | None, message: str, level: str = "info") -> None:
    if callable(log):
        log(message, level)


def _visible(element: Any) -> bool:
    try:
        displayed = getattr(element, "is_displayed", None)
        if callable(displayed) and not bool(displayed()):
            return False
    except Exception:
        return False
    try:
        enabled = getattr(element, "is_enabled", None)
        if callable(enabled) and not bool(enabled()):
            return False
    except Exception:
        pass
    try:
        if str(element.get_attribute("readonly") or "").casefold() in {"true", "readonly"}:
            return False
    except Exception:
        pass
    return True


def _attr(element: Any, name: str) -> str:
    try:
        return str(element.get_attribute(name) or "")
    except Exception:
        return ""


def _element_attrs(element: Any) -> str:
    return " ".join(
        _attr(element, name)
        for name in (
            "autocomplete", "inputmode", "aria-label", "placeholder", "name",
            "id", "type", "data-testid", "data-test-id", "data-slot", "class",
        )
    )


def _element_identity(element: Any) -> tuple[str, str]:
    """Return a WebDriver identity that survives JS and CSS wrapper changes."""
    for name in ("id", "_id"):
        try:
            value = getattr(element, name, None)
            if value:
                return name, str(value)
        except Exception:
            pass
    return "python", str(id(element))


def _find_all(driver: Any, selector: str) -> list[Any]:
    found: list[Any] = []
    try:
        # Avoid importing Selenium at module import time: the configuration and
        # preflight pages can run in environments where Selenium is absent.
        from selenium.webdriver.common.by import By

        found = list(driver.find_elements(By.CSS_SELECTOR, selector) or [])
    except Exception:
        try:
            found = list(driver.find_elements("css selector", selector) or [])
        except Exception:
            found = []
    # React auth pages have used an open shadow root and a same-origin iframe
    # for the verification form.  Query only same-origin DOM trees; a
    # cross-origin frame is intentionally ignored by the browser sandbox.
    try:
        result = driver.execute_script(
            """
            const selector = arguments[0];
            const output = [];
            const seen = new Set();
            const visit = root => {
              if (!root || !root.querySelectorAll) return;
              for (const el of root.querySelectorAll(selector)) {
                if (!seen.has(el)) { seen.add(el); output.push(el); }
                if (el.shadowRoot) visit(el.shadowRoot);
              }
              for (const host of root.querySelectorAll('*')) {
                if (host.shadowRoot) visit(host.shadowRoot);
              }
              for (const frame of root.querySelectorAll('iframe')) {
                try { if (frame.contentDocument) visit(frame.contentDocument); } catch (_) {}
              }
            };
            visit(document);
            return output.slice(0, 64);
            """,
            selector,
        ) or []
        if isinstance(result, list):
            seen_ids = {_element_identity(item) for item in found}
            for item in result:
                if item is None:
                    continue
                identity = _element_identity(item)
                if identity not in seen_ids:
                    seen_ids.add(identity)
                    found.append(item)
    except Exception:
        pass
    return found


def _select_active_auth_window(
    driver: Any,
    log: LogFn | None = None,
    *,
    preferred_state: str = "",
) -> None:
    """Select the OpenAI auth target among concurrently opened Roxy tabs.

    A Roxy profile can retain both the previous login/OTP tab and the current
    about-you tab.  Callers that know the current stage can bias the choice
    without changing the default OTP/session behavior.
    """
    try:
        handles = list(getattr(driver, "window_handles", []) or [])
        switch = getattr(getattr(driver, "switch_to", None), "window", None)
        if len(handles) <= 1 or not callable(switch):
            return
        current = str(getattr(driver, "current_window_handle", "") or "")
        scored: list[tuple[int, str]] = []
        for handle in handles:
            try:
                switch(handle)
                url = str(getattr(driver, "current_url", "") or "").casefold()
                score = 0
                auth_page = is_trusted_site_url(url, "auth.openai.com")
                chatgpt_page = is_trusted_site_url(url, "chatgpt.com")
                path = urlsplit(url).path.casefold()
                if auth_page:
                    score += 50
                if preferred_state == "profile" and auth_page and any(value in path for value in ("about-you", "/profile", "signup/profile", "create-account/profile")):
                    score += 60
                    # A stale about-you tab can retain the URL after its React
                    # tree has been torn down. Prefer the live form, not the
                    # empty shell, when multiple Roxy windows are present.
                    try:
                        probe = driver.execute_script(
                            """
                            const visible = el => !!el &&
                              !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length) &&
                              getComputedStyle(el).visibility !== 'hidden' &&
                              getComputedStyle(el).display !== 'none';
                            const controls = [...document.querySelectorAll(
                              'input,select,textarea,[role="textbox"],[role="spinbutton"],[contenteditable="true"]'
                            )].filter(visible).length;
                            const buttons = [...document.querySelectorAll('button,[role="button"]')].filter(visible).length;
                            return {controls, buttons};
                            """
                        )
                        if not isinstance(probe, Mapping):
                            probe = None
                        if probe is not None and int(probe.get("controls") or 0) <= 0:
                            score -= 55
                        elif probe is not None and int(probe.get("buttons") or 0) > 0:
                            score += 10
                    except Exception:
                        # Keep the URL score when a remote driver cannot run
                        # a probe; the subsequent DOM wait remains bounded.
                        pass
                if auth_page and any(value in path for value in ("/email-verification", "/email-otp")):
                    score += 40
                if preferred_state == "otp" and auth_page and any(value in path for value in ("/email-verification", "/email-otp")):
                    score += 60
                if auth_page and any(value in path for value in ("/log-in", "/sign-up", "/authorize")):
                    score += 15
                if chatgpt_page:
                    score += 5
                if score:
                    scored.append((score, str(handle)))
            except Exception:
                continue
        if scored:
            selected = max(scored, key=lambda item: item[0])[1]
            switch(selected)
            if selected != current:
                _log(log, f"已选择 OpenAI 活动认证窗口（窗口数={len(handles)}，页面={safe_page_location(driver)}）")
        elif current in handles:
            switch(current)
        elif handles:
            # If Selenium cannot report the original handle, do not leave the
            # driver on whichever tab happened to be visited last.
            switch(handles[0])
    except Exception:
        pass


def _is_otp_candidate(element: Any) -> bool:
    if not _visible(element):
        return False
    attrs = _element_attrs(element)
    lower = attrs.casefold()
    if any(token in lower for token in ("password", "email", "username", "search")):
        return False
    if _OTP_ATTR_RE.search(attrs):
        return True
    if _NUMERIC_RE.search(attrs):
        return True
    # A six-cell form sometimes has no semantic attributes.  A one-character
    # maxlength and a short width are enough to identify that layout later.
    maxlength = _attr(element, "maxlength")
    return maxlength == "1"


def _page_state(driver: Any) -> str:
    """Classify the page while waiting so a rendered transition is not hidden."""
    try:
        return str(classify_page(driver) or "unknown")
    except Exception:
        return "unknown"


def find_otp_inputs(driver: Any) -> list[Any]:
    """Return visible, editable OTP inputs in DOM order."""
    # Roxy can leave a stale tab selected while the auth tab is rendering.
    # Re-select the current live handle only when Selenium reports that the
    # current handle is no longer valid; this is best-effort and side-effect
    # free for normal single-window runs.
    _select_active_auth_window(driver)
    fields = [element for element in _find_all(driver, "input") if _is_otp_candidate(element)]
    if len(fields) > 6:
        # Keep the most likely group and avoid unrelated numeric controls.
        semantic = [field for field in fields if _OTP_ATTR_RE.search(_element_attrs(field))]
        fields = semantic or fields[:6]
    return fields


def _safe_input_summary(driver: Any) -> dict[str, Any]:
    fields = find_otp_inputs(driver)
    invalid = sum(_attr(field, "aria-invalid").casefold() == "true" for field in fields)
    try:
        handles = len(list(getattr(driver, "window_handles", []) or []))
    except Exception:
        handles = 0
    return {
        "input_count": len(fields),
        "invalid_count": invalid,
        "url": safe_page_location(driver),
        "window_count": handles,
    }


def wait_for_otp_input(driver: Any, timeout: int = 30, log: LogFn | None = None) -> list[Any]:
    """Wait for delayed OTP rendering and return the current input group."""
    started = time.monotonic()
    deadline = started + max(0.5, float(timeout or 30))
    last_count = -1
    while time.monotonic() < deadline:
        _select_active_auth_window(driver, log)
        state = _page_state(driver)
        if state == "security":
            state = wait_for_security_clear(driver, int(max(1, deadline - time.monotonic())), log)
        if state == "security":
            raise FreeRegisterError(
                "free_roxy_challenge", "等待注册页安全验证",
                f"等待验证码控件时进入安全验证页（{safe_page_location(driver)}）",
                retryable=False,
                error_code="free_roxy_security_challenge",
            )
        if state in {"home", "profile", "signup_password", "login_password", "oauth_callback"}:
            raise FreeRegisterError(
                "free_email_otp_validate", "验证 Free 邮箱验证码",
                f"验证码控件出现前页面已进入 {state}（{safe_page_location(driver)}）",
                error_code="free_email_otp_input_missing",
            )
        fields = find_otp_inputs(driver)
        if fields:
            if len(fields) != last_count:
                _log(log, f"验证码输入框已出现：数量={len(fields)}，位置={safe_page_location(driver)}")
                last_count = len(fields)
            return fields
        time.sleep(0.35)
    summary = _safe_input_summary(driver)
    elapsed = int((time.monotonic() - started) * 1000)
    raise FreeRegisterError(
        "free_email_otp_validate", "验证 Free 邮箱验证码",
        f"等待验证码输入框超时（{elapsed}ms，inputs={summary['input_count']}，"
        f"windows={summary['window_count']}，{summary['url']}）",
        error_code="free_email_otp_input_wait_timeout",
    )


def clear_otp_inputs(driver: Any, fields: list[Any] | None = None) -> list[Any]:
    """Clear every OTP field before a retry so an old code cannot be mixed in."""
    fields = list(fields or find_otp_inputs(driver))
    for field in fields:
        cleared = False
        try:
            field.clear()
            cleared = True
        except Exception:
            pass
        if not cleared:
            try:
                from selenium.webdriver.common.keys import Keys

                field.send_keys(Keys.COMMAND, "a", Keys.BACKSPACE)
                cleared = True
            except Exception:
                try:
                    field.send_keys("\ue009", "a", "\ue003")
                    cleared = True
                except Exception:
                    pass
        if not cleared:
            raise FreeRegisterError(
                "free_email_otp_validate", "验证 Free 邮箱验证码",
                "验证码输入框无法清空，已停止重复提交",
                error_code="free_email_otp_input_clear_failed",
            )
    return fields


def _find_submit(driver: Any, fields: list[Any]) -> Any | None:
    candidates = [element for element in _find_all(driver, "button, input[type='submit'], [role='button']") if _visible(element)]
    scored: list[tuple[int, int, Any]] = []
    for index, element in enumerate(candidates):
        attrs = _element_attrs(element)
        text = _attr(element, "value") or _attr(element, "aria-label") or _attr(element, "title")
        try:
            text = text or str(element.text or "")
        except Exception:
            pass
        haystack = f"{attrs} {text}".casefold()
        if any(token in haystack for token in ("resend", "again", "重新发送", "重发", "再送信")):
            continue
        if _attr(element, "aria-disabled").casefold() == "true":
            continue
        score = 0
        if _attr(element, "type").casefold() == "submit":
            score += 10
        if re.search(r"continue|verify|submit|confirm|next|继续|验证|確認|次へ", haystack, re.IGNORECASE):
            score += 5
        if score:
            scored.append((score, -index, element))
    if scored:
        return max(scored, key=lambda item: (item[0], item[1]))[2]
    return None


def _click_submit(driver: Any, fields: list[Any]) -> bool:
    if _wait_for_auto_submission(driver, timeout=0.12):
        return False
    try:
        probe = read_otp_validate_probe(driver)
        state = _page_state(driver)
        if probe.get("submit_observed") or probe.get("rows") or state in {
            "security", "home", "profile", "signup_password", "login_password", "oauth_callback",
        }:
            return False
    except Exception:
        pass
    button = _find_submit(driver, fields)
    if button is not None:
        try:
            button.click()
            return True
        except Exception:
            try:
                driver.execute_script("arguments[0].click();", button)
                return True
            except Exception:
                pass
    # Some versions auto-submit when the sixth character is entered.  If there
    # is a form but no visible button, let the page handle that path and let
    # wait_after_otp_submit classify the result.
    try:
        return bool(driver.execute_script(
            """
            const input = arguments[0]; const form = input && input.closest ? input.closest('form') : null;
            if (!form) return false;
            if (typeof form.requestSubmit === 'function') { form.requestSubmit(); return true; }
            HTMLFormElement.prototype.submit.call(form); return true;
            """,
            fields[0] if fields else None,
        ))
    except Exception:
        return False


def _wait_for_auto_submission(driver: Any, timeout: float = 0.35) -> bool:
    """Give six-cell forms a short window to submit on the final digit."""
    deadline = time.monotonic() + max(0.05, float(timeout or 0.35))
    checks = 0
    while time.monotonic() < deadline and checks < 8:
        checks += 1
        try:
            probe = read_otp_validate_probe(driver)
            if probe.get("submit_observed") or probe.get("rows"):
                return True
            if _page_state(driver) in {
                "security", "home", "profile", "signup_password", "login_password", "oauth_callback",
            }:
                return True
        except Exception:
            pass
        time.sleep(0.05)
    return False


def install_otp_validate_probe(driver: Any) -> dict[str, Any]:
    """Observe only safe metadata from the same-origin OTP validation call."""
    script = r"""
    (() => {
      const key = '__gptphone_email_otp_validate__';
      const generation = Number(window.__gptphone_email_otp_probe_generation || 0) + 1;
      const safe = (url, status, contentType, body, requestGeneration) => {
        try {
          if (!String(url || '').includes('/api/accounts/email-otp/validate')) return;
          let code = '';
          let continueUrl = '';
          try {
            const value = JSON.parse(String(body || '')) || {};
            const error = value.error && typeof value.error === 'object' ? value.error : {};
            const candidate = error.error_code || error.errorCode || value.error_code || value.errorCode || error.code || value.code || '';
            const text = String(candidate || '').trim();
            // A numeric code may be the OTP itself. Keep only symbolic codes.
            code = /^(?!\d{4,8}$)[A-Za-z][A-Za-z0-9_.:-]{0,79}$/.test(text) ? text : '';
            const page = value.page && typeof value.page === 'object' ? value.page : {};
            const candidateUrl = value.continue_url || value.external_url || value.url
              || page.continue_url || page.external_url || page.url || '';
            try {
              const parsed = new URL(String(candidateUrl || ''), location.origin);
              if (parsed.protocol === 'https:' && (parsed.hostname === 'auth.openai.com' || parsed.hostname === 'chatgpt.com')) {
                continueUrl = parsed.href;
              }
            } catch (_) {}
          } catch (_) {}
          (window[key] ||= []).push({status:Number(status || 0), contentType:String(contentType || '').split(';')[0],
            errorCode:code.slice(0, 80), requestGeneration:Number(requestGeneration || generation),
            continueUrl:continueUrl.slice(0, 2048),
            ok:Number(status || 0) >= 200 && Number(status || 0) < 300, ts:Date.now()});
        } catch (_) {}
      };
      window.__gptphone_email_otp_probe_generation = generation;
      window.__gptphone_email_otp_submit_observed = false;
      window[key] = [];
      if (window.__gptphone_email_otp_validate_hooked) return {installed:true, submit_observed:false, generation};
      window.__gptphone_email_otp_validate_hooked = true;
      // Delegate from document so delayed React forms and a refreshed OTP
      // page are observed without installing duplicate listeners.
      document.addEventListener('submit', () => {
        window.__gptphone_email_otp_submit_observed = true;
      }, true);
      const fetch0 = window.fetch;
      if (fetch0) window.fetch = async function(input, init) {
        const requestGeneration = Number(window.__gptphone_email_otp_probe_generation || generation);
        try {
          const url = typeof input === 'string' ? input : (input && input.url);
          if (String(url || '').includes('/api/accounts/email-otp/validate')) window.__gptphone_email_otp_submit_observed = true;
        } catch (_) {}
        const response = await fetch0.apply(this, arguments);
        try { const url = typeof input === 'string' ? input : (input && input.url); response.clone().text().then(body => safe(url, response.status, response.headers.get('content-type'), body, requestGeneration)).catch(() => {}); } catch (_) {}
        return response;
      };
      const open0 = XMLHttpRequest.prototype.open, send0 = XMLHttpRequest.prototype.send;
      XMLHttpRequest.prototype.open = function(method, url) {
        this.__gptphoneOtpUrl = url;
        this.__gptphoneOtpGeneration = Number(window.__gptphone_email_otp_probe_generation || generation);
        return open0.apply(this, arguments);
      };
      XMLHttpRequest.prototype.send = function() {
        try {
          if (String(this.__gptphoneOtpUrl || '').includes('/api/accounts/email-otp/validate')) window.__gptphone_email_otp_submit_observed = true;
          this.addEventListener('loadend', () => safe(this.__gptphoneOtpUrl, this.status, this.getResponseHeader('content-type'), this.responseText || '', this.__gptphoneOtpGeneration));
        } catch (_) {}
        return send0.apply(this, arguments);
      };
      return {installed:true, submit_observed:!!window.__gptphone_email_otp_submit_observed};
    })();
    """
    try:
        result = driver.execute_script(script) or {}
        return dict(result) if isinstance(result, Mapping) else {}
    except Exception:
        return {}


def _read_probe(driver: Any) -> list[dict[str, Any]]:
    try:
        result = driver.execute_script(
            "const generation=Number(window.__gptphone_email_otp_probe_generation||0);"
            "return (window.__gptphone_email_otp_validate__||[]).filter(item => "
            "Number(item && item.requestGeneration || generation) === generation);"
        ) or []
        return [dict(item) for item in result if isinstance(item, Mapping)] if isinstance(result, list) else []
    except Exception:
        return []


def _safe_error_code(value: Any) -> str:
    text = clean(value, 80)
    if re.fullmatch(r"\d{4,8}", text):
        return ""
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.:-]{0,79}", text):
        return ""
    return text


def _safe_continue_url(value: Any) -> str:
    """Keep OAuth callback URLs in memory only and restrict them to OpenAI hosts."""
    text = str(value or "").strip()
    if not text:
        return ""
    candidate = urljoin("https://auth.openai.com/", text)
    parsed = urlsplit(candidate)
    if parsed.scheme != "https" or parsed.hostname not in {"auth.openai.com", "chatgpt.com"}:
        return ""
    if not parsed.path or len(candidate) > 2048:
        return ""
    return candidate


def read_otp_validate_probe(driver: Any) -> dict[str, Any]:
    """Return a redacted validation summary for account-level diagnostics."""
    try:
        state = driver.execute_script(
            """
            const rows = window.__gptphone_email_otp_validate__ || [];
            const generation = Number(window.__gptphone_email_otp_probe_generation || 0);
            return {hooked:!!window.__gptphone_email_otp_validate_hooked,
              submit_observed:!!window.__gptphone_email_otp_submit_observed,
              rows:Array.isArray(rows) ? rows.filter(item => Number(item && item.requestGeneration || generation) === generation).slice(-12) : []};
            """
        ) or {}
    except Exception:
        state = {}
    if not isinstance(state, Mapping):
        state = {}
    rows = [dict(item) for item in state.get("rows") or [] if isinstance(item, Mapping)]
    if not rows and not state.get("hooked"):
        return {"installed": False, "submit_observed": bool(state.get("submit_observed")), "continue_url": "", "rows": []}
    latest = rows[-1] if rows else {}
    return {
        "installed": bool(state.get("hooked") or rows),
        "submit_observed": bool(state.get("submit_observed")),
        "continue_url": _safe_continue_url(latest.get("continueUrl") or latest.get("continue_url")),
        "status": latest.get("status"),
        "content_type": latest.get("contentType") or latest.get("content_type") or "",
        "error_code": _safe_error_code(latest.get("errorCode") or latest.get("error_code")),
        "rows": [
            {
                "status": item.get("status"),
                "content_type": item.get("contentType") or item.get("content_type") or "",
                "error_code": _safe_error_code(item.get("errorCode") or item.get("error_code")),
            }
            for item in rows[-3:]
        ],
    }


def follow_oauth_continue(driver: Any, continue_url: str, timeout: int = 45, log: LogFn | None = None) -> str:
    """Navigate one trusted OAuth callback and return the resulting page state."""
    target = _safe_continue_url(continue_url)
    if not target:
        raise FreeRegisterError(
            "free_oauth_callback", "完成 Free OAuth 回调",
            "OTP 校验返回的 OAuth 回调地址不受信任或为空",
            error_code="free_oauth_continue_url_invalid",
        )
    try:
        driver.get(target)
    except Exception as exc:
        current = _safe_continue_url(getattr(driver, "current_url", ""))
        if not current:
            raise FreeRegisterError(
                "free_oauth_callback", "完成 Free OAuth 回调",
                f"跟随 OAuth 回调失败（{type(exc).__name__}）",
                error_code="free_oauth_continue_navigation_failed",
            ) from exc
    state = wait_after_otp_submit(driver, timeout, log)
    _log(log, f"已跟随受信任 OAuth 回调，页面状态={state}，位置={safe_page_location(driver)}")
    return state


def wait_for_continue_url(driver: Any, timeout: float = 2.0) -> str:
    """Allow the response-body observer to finish without exposing its payload."""
    deadline = time.monotonic() + max(0.0, float(timeout or 0.0))
    while time.monotonic() <= deadline:
        value = read_otp_validate_probe(driver).get("continue_url")
        if value:
            return str(value)
        time.sleep(0.05)
    return ""


def _page_error(driver: Any) -> str:
    snapshot = page_snapshot(driver)
    body = str(snapshot.get("body") or "")
    if _ERROR_RE.search(body):
        return "页面明确提示验证码无效或已过期"
    for item in snapshot.get("inputs") or []:
        if isinstance(item, Mapping) and str(item.get("aria-invalid") or item.get("ariaInvalid") or "").casefold() == "true":
            return "验证码输入框被页面标记为无效"
    # Older page_snapshot implementations only expose an ``aria`` field.  A
    # direct bounded query keeps invalid-state detection compatible without
    # changing the shared page-flow module.
    try:
        result = driver.execute_script(r"""
          const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length);
          const errors = [...document.querySelectorAll('[role=alert],[aria-invalid=true],[class*="error" i],[id$="-error"]')]
            .filter(visible).map(el => String(el.innerText || el.textContent || '')).join(' ');
          const invalid = [...document.querySelectorAll('input[aria-invalid=true]')].some(visible);
          return {invalid, error: errors.slice(0, 500)};
        """) or {}
        if isinstance(result, Mapping):
            if bool(result.get("invalid")):
                return "验证码输入框被页面标记为无效"
            if _ERROR_RE.search(str(result.get("error") or "")):
                return "页面明确提示验证码无效或已过期"
    except Exception:
        pass
    return ""


def wait_after_otp_submit(driver: Any, timeout: int = 45, log: LogFn | None = None) -> str:
    """Wait for a real OTP transition and classify validation failures."""
    started = time.monotonic()
    deadline = started + max(1.0, float(timeout or 45))
    last_state = ""
    last_probe_signature = ""
    while time.monotonic() < deadline:
        state = classify_page(driver)
        if state == "security":
            state = wait_for_security_clear(driver, int(max(1, deadline - time.monotonic())), log)
        if state != last_state:
            _log(log, f"OTP 提交后页面状态：{state}，位置={safe_page_location(driver)}")
            last_state = state
        if state in {"signup_password", "login_password", "profile", "oauth_callback", "home", "security"}:
            return state
        if state == "otp":
            rows = _read_probe(driver)
            if rows:
                latest = rows[-1]
                status = int(latest.get("status") or 0)
                continue_url = _safe_continue_url(latest.get("continueUrl") or latest.get("continue_url"))
                if 200 <= status < 300 and continue_url:
                    _log(log, "邮箱验证码认证已返回 OAuth 回调，等待跟随受信任地址", "info")
                    return "oauth_callback"
                probe_signature = "|".join(str(latest.get(key) or "") for key in ("status", "contentType", "errorCode"))
                if probe_signature and probe_signature != last_probe_signature:
                    _log(
                        log,
                        "邮箱验证码认证请求已观察"
                        f"（HTTP {status or '-'}，Content-Type={latest.get('contentType') or '-'}，"
                        f"错误码={_safe_error_code(latest.get('errorCode')) or '-'}）",
                        "warn" if status >= 400 else "info",
                    )
                    last_probe_signature = probe_signature
                if 400 <= status < 500 and status != 429:
                    provider_code = _safe_error_code(latest.get("errorCode"))
                    terminal_provider_codes = {
                        "account_deactivated",
                        "account_banned",
                        "account_suspended",
                    }
                    terminal = provider_code in terminal_provider_codes
                    error = FreeRegisterError(
                        "free_email_otp_validate", "验证 Free 邮箱验证码",
                        (
                            "邮箱验证码被认证接口拒绝"
                            + (f"，Provider code {provider_code}" if provider_code else "")
                        ),
                        provider_status=status or None,
                        provider_code=provider_code,
                        # Terminal account classifications must not be hidden
                        # by a later stale-code timeout. The task can still be
                        # explicitly rerun after the mailbox is restored.
                        retryable=not terminal,
                        error_code=(
                            f"free_email_otp_{provider_code}"
                            if terminal and provider_code
                            else "free_email_otp_invalid"
                        ),
                    )
                    error.otp_submitted = True
                    raise error
                if status == 429 or status >= 500:
                    error = FreeRegisterError(
                        "free_email_otp_validate", "验证 Free 邮箱验证码",
                        f"邮箱验证码认证接口暂时失败（HTTP {status}）",
                        provider_status=status,
                        retryable=True,
                        error_code="free_email_otp_validate_failed",
                    )
                    error.otp_submitted = True
                    raise error
            error = _page_error(driver)
            if error:
                failure = FreeRegisterError(
                    "free_email_otp_validate", "验证 Free 邮箱验证码", error,
                    error_code="free_email_otp_invalid", retryable=True,
                )
                # A visible invalid/expired-code banner is emitted after the
                # page processed the form, even when the fetch probe missed a
                # framework-specific request wrapper.
                failure.otp_submitted = True
                raise failure
        time.sleep(0.5)
    elapsed = int((time.monotonic() - started) * 1000)
    probe = read_otp_validate_probe(driver)
    if not probe.get("submit_observed") and not probe.get("rows"):
        failure = FreeRegisterError(
            "free_email_otp_validate", "验证 Free 邮箱验证码",
            f"验证码提交后未观察到认证请求（{elapsed}ms，{safe_page_location(driver)}）",
            error_code="free_email_otp_submit_not_observed",
        )
        failure.otp_submitted = False
        raise failure
    failure = FreeRegisterError(
        "free_email_otp_validate", "验证 Free 邮箱验证码",
        f"验证码提交后仍停留在验证码页（{elapsed}ms，{safe_page_location(driver)}）",
        error_code="free_email_otp_transition_timeout",
    )
    failure.otp_submitted = bool(probe.get("submit_observed") or probe.get("rows"))
    raise failure


def run_otp_attempts(
    *,
    wait_code: OtpWaitFn,
    submit_code: OtpSubmitFn,
    restart_flow: OtpRestartFn,
    reload_flow: OtpRestartFn | None = None,
    log: LogFn | None = None,
    max_attempts: int = 3,
) -> str:
    """Run bounded OTP attempts while excluding every submitted code."""
    retryable_codes = {
        "free_email_otp_input_wait_timeout", "free_email_otp_input_missing",
        "free_email_otp_input_clear_failed", "free_email_otp_input_failed",
        "free_email_otp_submit_not_observed", "free_email_otp_invalid",
        "free_email_otp_validate_failed", "free_email_otp_transition_timeout",
        "free_email_otp_wait_mailbox_code_timeout", "free_email_otp_wait_mailbox_request_failed",
        "free_email_otp_code_reused",
    }
    used_codes: set[str] = set()
    pending_code = ""
    reload_used = False
    # These failures happen before a real validation request. Reuse the same
    # code once after an in-profile reload before asking the mailbox for a new
    # message, preventing a delayed input from consuming a fresh OTP.
    pre_submit_codes = {
        "free_email_otp_input_wait_timeout", "free_email_otp_input_missing",
        "free_email_otp_input_clear_failed", "free_email_otp_input_failed",
        "free_email_otp_submit_not_observed",
        "free_email_otp_reload_failed", "free_email_otp_reload_timeout",
    }
    attempts = min(3, max(1, int(max_attempts or 3)))
    for attempt in range(1, attempts + 1):
        submitted_code = ""
        try:
            # A page-rendering failure must not consume the code already read
            # from the mailbox.  Reuse it after the controlled page reload.
            submitted_code = pending_code or str(wait_code(attempt) or "").strip()
            pending_code = ""
            if not re.fullmatch(r"\d{6}", submitted_code):
                raise FreeRegisterError(
                    "free_email_otp_validate", "验证 Free 邮箱验证码",
                    "邮箱取件返回的验证码格式无效",
                    error_code="free_email_otp_code_invalid_format", retryable=True,
                )
            if submitted_code in used_codes:
                raise FreeRegisterError(
                    "free_email_otp_validate", "验证 Free 邮箱验证码",
                    "取件接口返回了本任务已经提交过的旧验证码",
                    error_code="free_email_otp_code_reused", retryable=True,
                )
            result = submit_code(submitted_code, attempt)
            # Only a successful return from submit_code (which waits for a
            # transition after the browser request) consumes the code.
            used_codes.add(submitted_code)
            return result
        except FreeRegisterError as exc:
            error_code = str(getattr(exc, "error_code", "") or "")
            # Validation, transition and server errors happen after the
            # browser submission has been attempted. Keep that code excluded
            # even though submit_code raised; pre-submit input errors are the
            # only cases eligible for same-page reuse.
            submission_marker = getattr(exc, "otp_submitted", None)
            actually_submitted = (
                bool(submission_marker)
                if submission_marker is not None
                else error_code not in pre_submit_codes
            )
            if submitted_code and actually_submitted:
                used_codes.add(submitted_code)
            can_retry = bool(getattr(exc, "retryable", True)) and (
                error_code in retryable_codes or error_code.startswith("free_email_otp_wait_")
            )
            if not can_retry or attempt >= attempts:
                raise
            if submitted_code and not actually_submitted and callable(reload_flow) and not reload_used:
                try:
                    reload_used = True
                    _log(log, "验证码控件未就绪或未触发提交，先在同一 Profile 原页刷新并重用当前验证码", "warn")
                    same_page_state = reload_flow(attempt)
                    if same_page_state == "otp":
                        pending_code = submitted_code
                        _log(log, "同一验证码页已恢复，下一次尝试继续复用已取得验证码", "info")
                        continue
                except FreeRegisterError as same_page_exc:
                    same_page_code = str(getattr(same_page_exc, "error_code", "") or "")
                    same_page_marker = getattr(same_page_exc, "otp_submitted", None)
                    same_page_submitted = (
                        bool(same_page_marker)
                        if same_page_marker is not None
                        else same_page_code not in pre_submit_codes
                    )
                    if same_page_submitted:
                        raise
            if submitted_code and not actually_submitted:
                # Keep the code for the next bounded attempt.  The restart
                # callback may rebuild the same OTP page, but it must not
                # force a new mailbox request until a submit was observed.
                pending_code = submitted_code
            _log(
                log,
                f"邮箱验证码阶段失败，准备在同一 Profile 重新触发第 {attempt + 1}/{attempts} 次"
                f"（错误节点={error_code or 'free_email_otp_failed'}，不更换代理/IP）",
                "warn",
            )
            try:
                next_state = restart_flow(attempt + 1)
            except FreeRegisterError as restart_exc:
                _log(
                    log,
                    f"重新触发邮箱验证码失败，保留原始 OTP 错误节点"
                    f"（{getattr(restart_exc, 'error_code', type(restart_exc).__name__)}）",
                    "error",
                )
                raise exc
            if next_state != "otp":
                return next_state
    raise FreeRegisterError(
        "free_email_otp_validate", "验证 Free 邮箱验证码",
        "邮箱验证码达到最大尝试次数",
        error_code="free_email_otp_attempts_exhausted", retryable=False,
    )


def reopen_email_otp_flow(
    driver: Any,
    email: str,
    account_flow: str,
    otp: Any,
    stage_code: str,
    human: Any,
    log: LogFn,
    timeout: int,
    *,
    open_signup_page: Callable[[Any, str, int], None],
    classify: Callable[[Any], str],
    find_element: Callable[[Any, list[str], int], Any],
    type_element: Callable[[Any, str, Any], None],
    submit: Callable[[Any, Any], None],
    wait_after_email_submit: Callable[[Any, int, LogFn | None], str],
    switch_login_to_email_code: Callable[[Any, Any, LogFn | None], None],
    wait_after_passwordless_switch: Callable[[Any, int, LogFn | None], str],
    submit_signup_password: Callable[[Any, Any, LogFn], str],
    submit_email: Callable[[Any, str, Any, LogFn | None, int], str] | None = None,
) -> str:
    """Re-open the same Roxy Profile and request a new mailbox OTP."""
    started = time.monotonic()
    open_signup_page(driver, email, timeout)
    if callable(getattr(human, "delay", None)):
        human.delay("navigate")
    state = classify(driver)
    if state == "security":
        state = wait_for_security_clear(driver, timeout, log)
    if state == "security":
        raise FreeRegisterError(
            "free_roxy_challenge", "等待注册页安全验证",
            f"重新触发邮箱验证码时进入安全验证页（{safe_page_location(driver)}）",
            retryable=False, error_code="free_roxy_security_challenge",
        )
    if state == "otp":
        otp.mark_sent(stage_code)
        _log(log, f"重新打开授权后已在邮箱验证码页，继续等待新验证码（duration_ms={int((time.monotonic() - started) * 1000)}）")
        return state
    if state == "login_password":
        if account_flow != "existing_login":
            raise FreeRegisterError(
                "free_roxy_login_password", "识别登录密码页",
                f"重新触发验证码时进入登录密码页（{safe_page_location(driver)}）",
                retryable=False, error_code="free_roxy_login_password_page",
            )
        switch_login_to_email_code(driver, human, log)
        state = wait_after_passwordless_switch(driver, timeout, log)
    elif state not in {"signup_password", "profile", "home", "oauth_callback"}:
        try:
            if submit_email is not None:
                state = submit_email(driver, email, human, log, timeout)
            else:
                field = find_element(
                    driver,
                    ["input[type='email']", "input[name='email']", "input[autocomplete='email']", "input[name='username']"],
                    min(45, max(10, timeout)),
                )
                type_element(field, email, human)
                submit(driver, human)
                if callable(getattr(human, "delay", None)):
                    human.delay("navigate")
                state = wait_after_email_submit(driver, timeout, log)
        except FreeRegisterError:
            raise
        except Exception as exc:
            raise FreeRegisterError(
                "free_roxy_signup_email_submit", "提交 Free 注册邮箱",
                f"重新触发邮箱验证码时提交邮箱失败（{type(exc).__name__}，{safe_page_location(driver)}）",
                error_code="free_roxy_signup_email_submit_failed",
            ) from exc
    if state == "signup_password":
        state = submit_signup_password(driver, human, log)
    if state == "otp":
        otp.mark_sent(stage_code)
        _log(log, f"已重新触发邮箱验证码，页面确认进入 OTP（duration_ms={int((time.monotonic() - started) * 1000)}）", "success")
    return state


def reload_otp_page(driver: Any, timeout: int = 30, log: LogFn | None = None) -> str:
    """Reload the current OTP page in the same Profile without requesting mail."""
    started = time.monotonic()
    try:
        refresh = getattr(driver, "refresh", None)
        if not callable(refresh):
            raise RuntimeError("Selenium refresh 不可用")
        refresh()
    except Exception as exc:
        raise FreeRegisterError(
            "free_email_otp_input_missing", "验证 Free 邮箱验证码",
            f"同 Profile 刷新验证码页失败（{type(exc).__name__}，{safe_page_location(driver)}）",
            error_code="free_email_otp_reload_failed",
        ) from exc
    deadline = time.monotonic() + max(3, int(timeout or 30))
    while time.monotonic() < deadline:
        state = _page_state(driver)
        if state == "security":
            raise FreeRegisterError(
                "free_roxy_challenge", "等待注册页安全验证",
                f"刷新验证码页后进入安全验证页（{safe_page_location(driver)}）",
                retryable=False, error_code="free_roxy_security_challenge",
            )
        if state == "otp":
            _log(log, f"同 Profile 验证码页刷新完成，复用当前验证码（duration_ms={int((time.monotonic() - started) * 1000)}）", "info")
            return state
        time.sleep(0.35)
    raise FreeRegisterError(
        "free_email_otp_input_missing", "验证 Free 邮箱验证码",
        f"同 Profile 刷新后未回到验证码页（{safe_page_location(driver)}）",
        error_code="free_email_otp_reload_timeout",
    )


def fill_otp(driver: Any, code: str, human: Any | None = None) -> dict[str, Any]:
    """Clear, fill and submit one OTP without exposing its value."""
    normalized = str(code or "").strip()
    if not re.fullmatch(r"\d{6}", normalized):
        raise FreeRegisterError(
            "free_email_otp_validate", "验证 Free 邮箱验证码",
            "邮箱验证码格式无效（需要六位数字）",
            error_code="free_email_otp_code_invalid_format",
        )
    fields = wait_for_otp_input(driver)
    clear_otp_inputs(driver, fields)
    # Install before typing: some auth builds submit automatically as soon as
    # the final cell receives its digit.
    installed = install_otp_validate_probe(driver)
    if callable(getattr(human, "delay", None)):
        human.delay("otp_input")
    maxlengths = [_attr(field, "maxlength") for field in fields[: len(normalized)]]
    separate_cells = len(fields) >= len(normalized) and (
        all(value == "1" for value in maxlengths)
        or len(fields) >= 6 and all(value in {"", "1"} for value in maxlengths)
    )
    single = not separate_cells
    if single:
        field = fields[0]
        try:
            field.send_keys(normalized)
        except Exception as exc:
            raise FreeRegisterError(
                "free_email_otp_validate", "验证 Free 邮箱验证码",
                f"验证码输入失败（{type(exc).__name__}）",
                error_code="free_email_otp_input_failed",
            ) from exc
    else:
        for field, character in zip(fields, normalized):
            field.send_keys(character)
            if callable(getattr(human, "delay", None)):
                human.delay("keystroke")
    auto_submitted = _wait_for_auto_submission(driver)
    clicked = False if auto_submitted else _click_submit(driver, fields)
    probe = read_otp_validate_probe(driver)
    return {
        "input_count": len(fields),
        "submit_clicked": clicked,
        "submit_observed": bool(auto_submitted or probe.get("submit_observed") or probe.get("rows")),
        "probe": installed,
    }


__all__ = [
    "clear_otp_inputs", "fill_otp", "find_otp_inputs", "install_otp_validate_probe",
    "read_otp_validate_probe", "follow_oauth_continue", "wait_for_continue_url", "reload_otp_page", "reopen_email_otp_flow", "run_otp_attempts",
    "select_active_auth_window",
    "wait_after_otp_submit", "wait_for_otp_input",
]


select_active_auth_window = _select_active_auth_window
