"""Optional pay.153.ink browser adapter.

This adapter is deliberately isolated from the Free registration drivers.  It is
only loaded when the user selects the optional browser mode and never runs during
configuration or tests.
"""

from __future__ import annotations

import time
from typing import Any, Callable, Mapping


class Pay153BrowserError(RuntimeError):
    node_code = "payment_pay153_browser"
    node_label = "pay.153.ink 浏览器提链"
    error_code = "payment_pay153_browser_failed"
    retryable = True


def _visible(driver: Any, selector: str) -> Any | None:
    try:
        element = driver.find_element("css selector", selector)
        return element if element.is_displayed() else None
    except Exception:
        return None


def _set_value(element: Any, value: str) -> None:
    try:
        element.clear()
    except Exception:
        pass
    element.send_keys(value)


def extract_pay153_link(
    task: Mapping[str, Any],
    secret: Mapping[str, Any],
    config: Mapping[str, Any],
    *,
    stage: Callable[[str], None] | None = None,
    cancel_event: Any | None = None,
) -> str:
    """Extract one link from the optional pay.153.ink page.

    The selectors intentionally cover the stable form contract used by the
    reference project, while failures remain structured and do not expose the
    supplied token.  No payment action is performed.
    """
    def checkpoint(name: str) -> None:
        if cancel_event is not None and cancel_event.is_set():
            raise Pay153BrowserError("任务已取消")
        if stage:
            stage(name)

    try:
        from selenium import webdriver
        from selenium.common.exceptions import WebDriverException
        from selenium.webdriver.chrome.options import Options
    except Exception as exc:  # pragma: no cover - depends on optional runtime
        raise Pay153BrowserError("Selenium 未安装，无法启用 pay.153.ink 浏览器模式") from exc

    options = Options()
    if bool(config.get("pay153_headless", True)):
        options.add_argument("--headless=new")
    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    proxy = str(secret.get("checkout_proxy") or "").strip()
    if proxy:
        # Chrome accepts HTTP(S) proxy URLs here. SOCKS credentials should be
        # configured through a browser profile by the caller, not logged inline.
        from urllib.parse import urlsplit
        parsed = urlsplit(proxy)
        if parsed.hostname and parsed.port and parsed.scheme in {"http", "https", "socks5", "socks5h"}:
            options.add_argument(f"--proxy-server={parsed.scheme}://{parsed.hostname}:{parsed.port}")
    driver = None
    timeout = max(15, min(300, int(config.get("timeout_seconds") or 180)))
    try:
        checkpoint("payment_pay153_open")
        driver = webdriver.Chrome(options=options)
        driver.set_page_load_timeout(timeout)
        url = str(config.get("pay153_url") or "https://pay.153.ink/").strip()
        driver.get(url)
        checkpoint("payment_pay153_form")
        token = str(secret.get("access_token") or "").strip()
        if not token:
            raise Pay153BrowserError("没有可用 Token")
        token_input = next((
            _visible(driver, selector)
            for selector in ("input[name='token']", "textarea[name='token']", "input[placeholder*='Token']", "textarea")
        ), None)
        if token_input is None:
            raise Pay153BrowserError("页面未找到 Token 输入框")
        _set_value(token_input, token)
        for selector, value in (("select[name='plan']", str(task.get("plan") or "plus")), ("select[name='channel']", str(task.get("channel") or "paypal"))):
            field = _visible(driver, selector)
            if field is not None:
                try:
                    from selenium.webdriver.support.ui import Select
                    Select(field).select_by_value(value)
                except Exception:
                    pass
        submit = next((
            _visible(driver, selector)
            for selector in ("button[type='submit']", "button[data-action='extract']", "button")
        ), None)
        if submit is None:
            raise Pay153BrowserError("页面未找到提炼按钮")
        submit.click()
        checkpoint("payment_pay153_wait")
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            checkpoint("payment_pay153_wait")
            for selector in ("input[readonly]", "textarea[readonly]", "a[href*='cs_live_']", "a[href*='checkout']", "[data-result-url]"):
                element = _visible(driver, selector)
                if element is None:
                    continue
                try:
                    value = str(element.get_attribute("value") or element.get_attribute("href") or element.get_attribute("data-result-url") or element.text or "").strip()
                except Exception:
                    value = ""
                if value and ("cs_live_" in value or value.startswith(("http://", "https://"))):
                    return value
            time.sleep(0.25)
        raise Pay153BrowserError("页面在规定时间内未返回支付链接")
    except Pay153BrowserError:
        raise
    except WebDriverException as exc:
        raise Pay153BrowserError("浏览器驱动连接失败") from exc
    except Exception as exc:
        raise Pay153BrowserError("页面提链操作失败") from exc
    finally:
        if driver is not None:
            try:
                driver.quit()
            except Exception:
                pass


__all__ = ["Pay153BrowserError", "extract_pay153_link"]
