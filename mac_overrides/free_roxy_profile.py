"""Credential-safe profile-page handling for the Free Roxy flow."""

from __future__ import annotations

import time
from datetime import date
from typing import Any, Callable

try:
    from .free_register_common import FreeRegisterError, clean
    from .free_roxy_page_flow import classify_page, page_snapshot
    from .free_roxy_signup import safe_page_location
except ImportError:
    from free_register_common import FreeRegisterError, clean  # type: ignore[no-redef]
    from free_roxy_page_flow import classify_page, page_snapshot  # type: ignore[no-redef]
    from free_roxy_signup import safe_page_location  # type: ignore[no-redef]


LogFn = Callable[[str, str], None]


def _log(log: LogFn | None, message: str, level: str = "info") -> None:
    if callable(log):
        log(message, level)


def _visible(element: Any) -> bool:
    try:
        return bool(element.is_displayed()) and bool(element.is_enabled())
    except Exception:
        return False


def _find_first(driver: Any, selectors: list[str]) -> Any | None:
    for selector in selectors:
        try:
            elements = driver.find_elements("css selector", selector) or []
        except Exception:
            try:
                from selenium.webdriver.common.by import By
                elements = driver.find_elements(By.CSS_SELECTOR, selector) or []
            except Exception:
                elements = []
        for element in elements:
            if _visible(element):
                return element
    return None


def _type(element: Any, value: str, human: Any | None = None) -> None:
    try:
        element.clear()
    except Exception:
        pass
    if not bool(getattr(human, "actions", False)):
        element.send_keys(value)
        return
    for character in str(value):
        element.send_keys(character)
        delay = getattr(human, "delay", None)
        if callable(delay):
            delay("keystroke")


def _set_birthday(driver: Any, birthday: str, age: int) -> str:
    year, month, day = birthday.split("-")
    result = driver.execute_script(
        r"""
        const [year, month, day, age] = arguments;
        const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
          && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none'
          && !el.disabled && !el.readOnly;
        const setValue = (el, value) => {
          if (!el) return false;
          const tag = String(el.tagName || '').toLowerCase();
          const proto = tag === 'select' ? HTMLSelectElement.prototype : HTMLInputElement.prototype;
          const setter = Object.getOwnPropertyDescriptor(proto, 'value')?.set;
          if (setter) setter.call(el, String(value)); else el.value = String(value);
          el.dispatchEvent(new Event('input', {bubbles:true}));
          el.dispatchEvent(new Event('change', {bubbles:true}));
          el.blur?.();
          return true;
        };
        const ageInput = [...document.querySelectorAll('input[name="age"],input#age,input[type="number"]')]
          .find(visible);
        if (ageInput && setValue(ageInput, age)) return 'age';
        const dateInput = [...document.querySelectorAll('input[type="date"],input[name="birthday"],input[name="birthdate"]')]
          .find(el => visible(el) || String(el.type || '').toLowerCase() === 'date');
        if (dateInput && setValue(dateInput, `${year}-${String(month).padStart(2, '0')}-${String(day).padStart(2, '0')}`)) return 'birthday';
        const find = selectors => {
          for (const selector of selectors) {
            const item = [...document.querySelectorAll(selector)].find(visible);
            if (item) return item;
          }
          return null;
        };
        const fields = [
          [find(['select[name="year"]','input[name="year"]','[data-type="year"]','[aria-label*="year" i]']), year],
          [find(['select[name="month"]','input[name="month"]','[data-type="month"]','[aria-label*="month" i]']), Number(month)],
          [find(['select[name="day"]','input[name="day"]','[data-type="day"]','[aria-label*="day" i]']), Number(day)],
        ];
        const count = fields.reduce((total, [el, value]) => total + (setValue(el, value) ? 1 : 0), 0);
        return count === 3 ? 'ymd' : '';
        """,
        year,
        month,
        day,
        str(age),
    )
    mode = clean(result, 40)
    if mode:
        return mode
    try:
        result = driver.execute_script(
            r"""
            const [year, month, day] = arguments;
            const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
              && !el.disabled && !el.readOnly;
            const values = {year, month:String(Number(month)), day:String(Number(day))};
            let count = 0;
            for (const el of document.querySelectorAll('[role="spinbutton"],[data-type]')) {
              const type = String(el.getAttribute('data-type') || '').toLowerCase();
              if (visible(el) && values[type]) {
                el.focus();
                el.textContent = values[type];
                el.setAttribute('aria-valuenow', values[type]);
                el.dispatchEvent(new InputEvent('input', {bubbles:true, data:values[type]}));
                el.dispatchEvent(new Event('change', {bubbles:true}));
                count += 1;
              }
            }
            return count === 3 ? 'spinbutton' : '';
            """,
            year,
            month,
            day,
        )
    except Exception:
        result = ""
    return clean(result, 40)


def _accept_consents(driver: Any) -> int:
    try:
        result = driver.execute_script(
            r"""
            const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
              && !el.disabled;
            const checked = el => el.checked === true
              || String(el.getAttribute('aria-checked') || el.closest('[role="checkbox"]')?.getAttribute('aria-checked') || '').toLowerCase() === 'true';
            const all = [...document.querySelectorAll('input[type="checkbox"],[role="checkbox"]')]
              .filter(el => visible(el) || visible(el.closest('label')));
            let count = 0;
            for (const el of all) {
              if (checked(el)) continue;
              const target = el.closest('label') || el;
              try { target.click(); } catch (_) {}
              if (!checked(el)) {
                const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'checked')?.set;
                if (setter && el.tagName === 'INPUT') setter.call(el, true); else el.setAttribute('aria-checked', 'true');
                el.dispatchEvent(new Event('input', {bubbles:true}));
                el.dispatchEvent(new Event('change', {bubbles:true}));
              }
              if (checked(el)) count += 1;
            }
            return count;
            """,
        )
        return max(0, int(result or 0))
    except Exception:
        return 0


def _submit(driver: Any) -> bool:
    try:
        return bool(driver.execute_script(
            r"""
            const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
              && !el.disabled && String(el.getAttribute('aria-disabled') || '').toLowerCase() !== 'true';
            const forms = [...document.querySelectorAll('form')].filter(visible);
            for (const form of forms) {
              const button = [...form.querySelectorAll('button[type="submit"],input[type="submit"]')].find(visible);
              if (button) { button.scrollIntoView({block:'center'}); button.click(); return true; }
              if (typeof form.requestSubmit === 'function') { form.requestSubmit(); return true; }
            }
            const buttons = [...document.querySelectorAll('button[type="submit"],input[type="submit"]')].filter(visible);
            if (buttons.length) { buttons[0].click(); return true; }
            return false;
            """,
        ))
    except Exception:
        return False


def _profile_summary(driver: Any) -> dict[str, Any]:
    snapshot = page_snapshot(driver)
    inputs = snapshot.get("inputs") if isinstance(snapshot, dict) else []
    try:
        checkboxes = int(driver.execute_script("return document.querySelectorAll('input[type=checkbox],[role=checkbox]').length") or 0)
    except Exception:
        checkboxes = 0
    return {"url": safe_page_location(driver), "input_count": len(inputs or []), "checkbox_count": checkboxes}


def complete_profile_page(
    driver: Any,
    human: Any,
    name: str,
    birthday: str,
    *,
    timeout: int = 60,
    log: LogFn | None = None,
) -> bool:
    """Fill and submit about-you, then wait for a real transition."""
    end = time.monotonic() + max(5, int(timeout or 60))
    submitted = False
    refreshed = False
    last_submit = 0.0
    while time.monotonic() < end:
        state = classify_page(driver)
        if state == "home":
            return submitted
        if state == "security":
            raise FreeRegisterError(
                "free_roxy_challenge", "等待注册页安全验证",
                f"资料页提交后进入安全验证页（{safe_page_location(driver)}）",
                retryable=False,
                error_code="free_roxy_security_challenge",
            )
        if state != "profile":
            time.sleep(0.4)
            continue
        if not submitted or time.monotonic() - last_submit >= 4:
            name_field = _find_first(driver, [
                "input[name='name']", "input[name='fullName']", "input[name='full_name']",
                "input[autocomplete='name']", "input[placeholder*='name' i]", "input[aria-label*='name' i]",
            ])
            if name_field is None:
                raise FreeRegisterError(
                    "free_roxy_profile", "填写 Free 账号资料",
                    f"资料页未找到姓名输入框（{safe_page_location(driver)}）",
                    error_code="free_roxy_profile_name_missing",
                )
            _type(name_field, name, human)
            year, month, day = (int(value) for value in birthday.split("-"))
            today = date.today()
            age = today.year - year - ((today.month, today.day) < (month, day))
            birthday_mode = _set_birthday(driver, birthday, age)
            if not birthday_mode:
                raise FreeRegisterError(
                    "free_roxy_profile", "填写 Free 账号资料",
                    f"资料页未找到可用的年龄或生日控件（{safe_page_location(driver)}）",
                    error_code="free_roxy_profile_birthday_missing",
                )
            _accept_consents(driver)
            delay = getattr(human, "delay", None)
            if callable(delay):
                delay("form")
            if not _submit(driver):
                raise FreeRegisterError(
                    "free_roxy_profile", "提交 Free 账号资料",
                    f"资料页没有可用的提交按钮（{safe_page_location(driver)}）",
                    error_code="free_roxy_profile_submit_missing",
                )
            submitted = True
            last_submit = time.monotonic()
            _log(log, f"资料页已提交，等待 OAuth 跳转（{safe_page_location(driver)}）")
            continue
        if not refreshed and time.monotonic() - last_submit >= 4:
            try:
                driver.refresh()
                refreshed = True
                _log(log, "资料页提交后仍未跳转，已在同一 Profile 刷新一次", "warn")
            except Exception as exc:
                _log(log, f"资料页刷新兜底失败（{type(exc).__name__}）", "warn")
                refreshed = True
        time.sleep(0.4)
    summary = _profile_summary(driver)
    raise FreeRegisterError(
        "free_roxy_profile", "完成 Free 账号资料",
        f"资料页提交后未确认 OAuth 跳转（{summary['url']}，输入框={summary['input_count']}，复选框={summary['checkbox_count']}）",
        error_code="free_roxy_profile_transition_timeout",
    )


__all__ = ["complete_profile_page"]
