"""Selenium/CDP adapter for the isolated RoxyBrowser flow."""

from __future__ import annotations

import os
from typing import Any, Callable

try:
    from .free_register_common import FreeRegisterError
    from .free_roxy_client import RoxyOpenResult
except ImportError:
    from free_register_common import FreeRegisterError  # type: ignore[no-redef]
    from free_roxy_client import RoxyOpenResult  # type: ignore[no-redef]


def build_driver(opened: RoxyOpenResult):
    """Connect only to a Roxy-provided endpoint; never invoke Selenium Manager."""
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
    from selenium.webdriver.remote.webdriver import WebDriver as RemoteWebDriver

    options = Options()
    options.page_load_strategy = "eager"
    driver_path = str(opened.driver_path or "").strip()
    if opened.debugger_address and driver_path and os.path.isfile(driver_path):
        options.add_experimental_option("debuggerAddress", opened.debugger_address)
        driver = webdriver.Chrome(
            service=Service(executable_path=driver_path),
            options=options,
        )
    elif opened.webdriver_url:
        driver = RemoteWebDriver(command_executor=opened.webdriver_url, options=options)
    else:
        detail = (
            "RoxyBrowser 返回了调试地址，但未返回可用的专用 ChromeDriver，"
            "已禁止回退系统 Chrome/Selenium Manager"
            if opened.debugger_address else "RoxyBrowser 未返回可用的 Selenium 远程连接或专用 ChromeDriver"
        )
        raise FreeRegisterError(
            "free_roxy_connect", "连接 RoxyBrowser", detail,
            retryable=True, error_code="free_roxy_driver_unavailable",
        )
    _install_automation_mask(driver)
    return driver


def driver_source(opened: RoxyOpenResult) -> str:
    if opened.debugger_address and opened.driver_path and os.path.isfile(str(opened.driver_path)):
        return "roxy_chromedriver"
    if opened.webdriver_url:
        return "roxy_remote_webdriver"
    return "unavailable"


def _install_automation_mask(driver: Any) -> None:
    script = """
    Object.defineProperty(Navigator.prototype, 'webdriver', {get: () => undefined});
    if (!window.chrome) window.chrome = {}; if (!window.chrome.runtime) window.chrome.runtime = {};
    const originalQuery = window.navigator.permissions && window.navigator.permissions.query;
    if (originalQuery) {
      window.navigator.permissions.query = parameters => (
        parameters && parameters.name === 'notifications'
          ? Promise.resolve({state: Notification.permission})
          : originalQuery(parameters)
      );
    }
    """
    try:
        driver.execute_cdp_cmd("Page.addScriptToEvaluateOnNewDocument", {"source": script})
    except Exception:
        pass


def find_element(driver: Any, selectors: list[str], timeout: int):
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait

    def locate(current: Any):
        for selector in selectors:
            try:
                element = current.find_element(By.CSS_SELECTOR, selector)
                if element.is_displayed() and element.is_enabled():
                    return element
            except Exception:
                continue
        return False

    return WebDriverWait(driver, timeout).until(locate)


def click_element(driver: Any, element: Any, human: Any) -> None:
    try:
        driver.execute_script("arguments[0].scrollIntoView({block:'center'});", element)
    except Exception:
        pass
    human.delay("click")
    try:
        point = driver.execute_script(
            "const r=arguments[0].getBoundingClientRect();"
            "return {x:r.left+r.width*0.5,y:r.top+r.height*0.5};",
            element,
        ) or {}
        x, y = float(point.get("x") or 0), float(point.get("y") or 0)
        if x <= 0 or y <= 0:
            raise ValueError("invalid click point")
        driver.execute_cdp_cmd("Input.dispatchMouseEvent", {"type": "mouseMoved", "x": x, "y": y})
        for event in ("mousePressed", "mouseReleased"):
            driver.execute_cdp_cmd("Input.dispatchMouseEvent", {
                "type": event, "x": x, "y": y, "button": "left", "clickCount": 1,
            })
    except Exception:
        try:
            if not callable(getattr(driver, "execute_cdp_cmd", None)):
                element.click()
                return
            result = driver.execute_script(
                "arguments[0].dispatchEvent(new PointerEvent('pointerdown',{bubbles:true,pointerType:'mouse'}));"
                "arguments[0].dispatchEvent(new MouseEvent('mousedown',{bubbles:true}));"
                "arguments[0].dispatchEvent(new MouseEvent('mouseup',{bubbles:true}));"
                "arguments[0].click();",
                element,
            )
            if result is False:
                element.click()
        except Exception:
            element.click()


def type_element(element: Any, value: str, human: Any) -> None:
    from selenium.webdriver.common.keys import Keys

    try:
        element.send_keys(Keys.COMMAND, "a")
        element.send_keys(Keys.BACKSPACE)
    except Exception:
        try:
            element.clear()
        except Exception:
            pass
    if not human.actions:
        element.send_keys(value)
        return
    for character in value:
        element.send_keys(character)
        human.delay("keystroke")


def submit_form(
    driver: Any,
    human: Any,
    find_fn: Callable[[Any, list[str], int], Any] = find_element,
    click_fn: Callable[[Any, Any, Any], None] = click_element,
) -> None:
    button = find_fn(
        driver,
        ["button[type='submit']", "input[type='submit']", "button[data-testid*='continue']", "button[name='action']"],
        15,
    )
    click_fn(driver, button, human)


__all__ = [
    "build_driver", "click_element", "driver_source", "find_element",
    "submit_form", "type_element",
]
