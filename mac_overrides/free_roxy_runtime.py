"""RoxyBrowser API and Selenium registration driver for isolated Free runs."""

from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import hmac
import json
import random
import re
import time
from typing import Any, Callable, Mapping
from urllib.parse import unquote, urljoin, urlsplit

import requests

try:
    from .free_mailbox_otp import MailboxUrlOtpProvider
    from .free_register_common import (
        FIXED_PASSWORD,
        FreeRegisterError,
        clean,
        mask_proxy,
        plus_trial_from_accounts,
        random_birthdate,
        random_display_name,
        safe_log_message,
    )
    from .free_roxy_signup import is_email_verification_page, open_signup_page, safe_page_location
    from .free_roxy_session import extract_session, session_token
except ImportError:
    from free_mailbox_otp import MailboxUrlOtpProvider  # type: ignore[no-redef]
    from free_register_common import (  # type: ignore[no-redef]
        FIXED_PASSWORD,
        FreeRegisterError,
        clean,
        mask_proxy,
        plus_trial_from_accounts,
        random_birthdate,
        random_display_name,
        safe_log_message,
    )
    from free_roxy_signup import is_email_verification_page, open_signup_page, safe_page_location  # type: ignore[no-redef]
    from free_roxy_session import extract_session, session_token  # type: ignore[no-redef]


@dataclass(slots=True)
class RoxyOpenResult:
    profile_id: str
    raw: dict[str, Any]
    debugger_address: str | None = None
    webdriver_url: str | None = None
    ws_endpoint: str | None = None
    created_by_run: bool = False


def _dig(payload: Mapping[str, Any], *keys: str) -> Any:
    current: Any = payload
    for key in keys:
        if not isinstance(current, Mapping):
            return None
        current = current.get(key)
    return current


def _first(payload: Mapping[str, Any], paths: list[tuple[str, ...]]) -> str:
    for path in paths:
        value = _dig(payload, *path)
        if value is not None and str(value).strip():
            return str(value).strip()
    return ""


def _roxy_id(value: Any) -> str | int:
    text = str(value or "").strip()
    return int(text) if text.isdigit() else text


def proxy_to_roxy_info(proxy: str, check_channel: str = "IPRust.io") -> dict[str, Any]:
    parsed = urlsplit(str(proxy or "").strip())
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https", "socks5", "socks5h"}:
        raise FreeRegisterError(
            "free_roxy_proxy", "配置 RoxyBrowser 代理",
            f"RoxyBrowser 不支持当前代理协议：{scheme or '-'}", retryable=False,
        )
    if not parsed.hostname or not parsed.port:
        raise FreeRegisterError("free_roxy_proxy", "配置 RoxyBrowser 代理", "RoxyBrowser 代理缺少主机或端口", retryable=False)
    protocol = {"http": "HTTP", "https": "HTTPS", "socks5": "SOCKS5", "socks5h": "SOCKS5"}[scheme]
    result: dict[str, Any] = {
        "moduleId": 0,
        "proxyMethod": "custom",
        "proxyCategory": protocol,
        "ipType": "IPV4",
        "protocol": protocol,
        "host": parsed.hostname,
        "port": str(parsed.port),
        "checkChannel": str(check_channel or "IPRust.io"),
    }
    if parsed.username:
        result["proxyUserName"] = unquote(parsed.username)
    if parsed.password:
        result["proxyPassword"] = unquote(parsed.password)
    return result


class RoxyBrowserClient:
    def __init__(self, config: Mapping[str, Any], *, session: Any | None = None, log_fn: Callable[[str, str], None] | None = None) -> None:
        self.config = dict(config or {})
        self.api_base = str(self.config.get("api_base") or "http://127.0.0.1:50000").rstrip("/")
        self.http = session or requests.Session()
        self.log_fn = log_fn
        token = str(self.config.get("api_key") or "").strip()
        self.http.headers.update({"Accept": "application/json", "Content-Type": "application/json"})
        if token:
            self.http.headers.update({"token": token, "Authorization": f"Bearer {token}"})

    def _log(self, value: str, level: str = "info") -> None:
        if callable(self.log_fn):
            self.log_fn(safe_log_message(value), level)

    @staticmethod
    def _retryable(exc: BaseException) -> bool:
        text = str(exc or "").lower()
        return any(value in text for value in ("timeout", "connection", "temporarily", "http 429", "http 500", "http 502", "http 503", "http 504"))

    def request(
        self,
        method: str,
        path: str,
        *,
        body: Mapping[str, Any] | None = None,
        params: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        target = urljoin(self.api_base + "/", str(path or "").lstrip("/"))
        attempts = 1 if str(path).rstrip("/").endswith("/create") else int(self.config.get("api_retries") or 3)
        delay = float(self.config.get("api_retry_delay") or 2.0)
        last: BaseException | None = None
        for attempt in range(1, max(1, attempts) + 1):
            try:
                response = self.http.request(
                    str(method or "POST").upper(),
                    target,
                    json=dict(body or {}) if body is not None else None,
                    params=dict(params or {}) if params else None,
                    timeout=max(5, int(self.config.get("selenium_timeout") or 90)),
                )
                status = int(getattr(response, "status_code", 0) or 0)
                if not 200 <= status < 300:
                    raise FreeRegisterError(
                        "free_roxy_api", "调用 RoxyBrowser API", f"RoxyBrowser API 返回 HTTP {status}",
                        retryable=status in {429, 500, 502, 503, 504}, provider_status=status,
                    )
                try:
                    payload = response.json()
                except Exception as exc:
                    raise FreeRegisterError("free_roxy_api", "调用 RoxyBrowser API", "RoxyBrowser API 未返回 JSON") from exc
                if not isinstance(payload, Mapping):
                    raise FreeRegisterError("free_roxy_api", "调用 RoxyBrowser API", "RoxyBrowser API 响应格式无效")
                code = payload.get("code")
                if code not in (None, 0, 200, "0", "200") and payload.get("ok") is not True and payload.get("success") is not True:
                    message = clean(payload.get("message") or payload.get("msg") or payload.get("error"), 200)
                    raise FreeRegisterError("free_roxy_api", "调用 RoxyBrowser API", message or "RoxyBrowser API 返回失败")
                if attempt > 1:
                    self._log(f"[RoxyBrowser/free_roxy_api] API 第 {attempt} 次请求成功")
                return dict(payload)
            except Exception as exc:
                last = exc
                if attempt >= attempts or not self._retryable(exc):
                    if isinstance(exc, FreeRegisterError):
                        raise
                    raise FreeRegisterError(
                        "free_roxy_api", "调用 RoxyBrowser API", f"RoxyBrowser API 请求异常（{type(exc).__name__}）"
                    ) from exc
                time.sleep(delay * attempt)
        raise FreeRegisterError("free_roxy_api", "调用 RoxyBrowser API", f"RoxyBrowser API 请求失败（{type(last).__name__}）")

    @staticmethod
    def _workspace_items(payload: Mapping[str, Any]) -> list[dict[str, str]]:
        data = payload.get("data") if isinstance(payload.get("data"), Mapping) else payload
        rows = data.get("rows") or data.get("list") or data.get("records") if isinstance(data, Mapping) else []
        output: list[dict[str, str]] = []
        for row in rows if isinstance(rows, list) else []:
            if not isinstance(row, Mapping):
                continue
            workspace_id = str(row.get("id") or row.get("workspaceId") or "")
            workspace_name = str(row.get("workspaceName") or row.get("name") or workspace_id)
            projects = row.get("project_details") or row.get("projectDetails") or row.get("projects") or []
            if isinstance(projects, list) and projects:
                for project in projects:
                    if not isinstance(project, Mapping):
                        continue
                    project_id = str(project.get("projectId") or project.get("id") or "")
                    project_name = str(project.get("projectName") or project.get("name") or project_id)
                    output.append({"workspace_id": workspace_id, "workspace_name": workspace_name, "project_id": project_id, "project_name": project_name, "label": f"{workspace_name} / {project_name}"})
            elif workspace_id:
                output.append({"workspace_id": workspace_id, "workspace_name": workspace_name, "project_id": "", "project_name": "", "label": workspace_name})
        return output

    def list_workspaces(self) -> list[dict[str, str]]:
        return self._workspace_items(self.request("GET", str(self.config.get("workspace_list_path") or "/browser/workspace")))

    def create_profile(self, proxy: str) -> str:
        choices = [str(value) for value in self.config.get("os_choices") or ["Windows", "macOS"]]
        prefix = str(self.config.get("profile_name_prefix") or "rb")
        profile_name = f"{prefix}-{int(time.time() * 1000)}-{random.randrange(65536):04x}" if bool(self.config.get("random_profile_name", True)) else prefix
        body: dict[str, Any] = {
            "workspaceId": _roxy_id(self.config.get("workspace_id")),
            "projectId": _roxy_id(self.config.get("project_id")),
            "name": profile_name,
            "os": random.choice(choices or ["Windows", "macOS"]) if bool(self.config.get("random_os", True)) else (choices[0] if choices else "Windows"),
            "proxyInfo": proxy_to_roxy_info(proxy, str(self.config.get("proxy_check_channel") or "IPRust.io")),
        }
        if not body["projectId"]:
            body.pop("projectId")
        payload = self.request("POST", str(self.config.get("create_path") or "/browser/create"), body=body)
        profile_id = _first(payload, [
            ("id",), ("dirId",), ("profileId",), ("data", "id"), ("data", "dirId"), ("data", "profileId"),
        ])
        if not profile_id:
            raise FreeRegisterError("free_roxy_create", "创建 RoxyBrowser 环境", "创建成功但未返回 Profile ID")
        self._log(f"[创建 RoxyBrowser 环境/free_roxy_create] Profile={profile_id} proxy={mask_proxy(proxy)}")
        return profile_id

    @staticmethod
    def _connection_result(profile_id: str, payload: Mapping[str, Any]) -> RoxyOpenResult | None:
        data = payload.get("data") if isinstance(payload.get("data"), (Mapping, list)) else payload
        rows = data if isinstance(data, list) else [data]
        for row in rows:
            if not isinstance(row, Mapping):
                continue
            candidate = _first(row, [("dirId",), ("profileId",), ("id",), ("windowId",)])
            if candidate and str(candidate) != str(profile_id):
                continue
            debugger = _first(row, [
                ("debuggerAddress",), ("debuggingPortUrl",), ("http",), ("httpEndpoint",),
            ])
            port = _first(row, [("debuggingPort",), ("port",)])
            if not debugger and port.isdigit():
                debugger = f"127.0.0.1:{port}"
            webdriver_url = _first(row, [("webdriver",), ("webdriverUrl",), ("selenium",)]) or None
            ws_endpoint = _first(row, [("ws",), ("wsEndpoint",), ("ws_endpoint",), ("debuggerWsUrl",)]) or None
            if not debugger and ws_endpoint:
                parsed = urlsplit(ws_endpoint)
                if parsed.hostname and parsed.port:
                    debugger = f"{parsed.hostname}:{parsed.port}"
            if not debugger and not webdriver_url and not ws_endpoint:
                continue
            if debugger:
                debugger = debugger.replace("http://", "").replace("https://", "").split("/", 1)[0].strip()
            return RoxyOpenResult(
                str(profile_id), dict(payload), debugger or None, webdriver_url, ws_endpoint, True,
            )
        return None

    def connection_info(self, profile_id: str) -> RoxyOpenResult | None:
        payload = self.request(
            "GET",
            str(self.config.get("connection_info_path") or "/browser/connection_info"),
            params={"dirIds": str(_roxy_id(profile_id))},
        )
        return self._connection_result(profile_id, payload)

    def open_profile(self, profile_id: str) -> RoxyOpenResult:
        body = {
            "workspaceId": _roxy_id(self.config.get("workspace_id")),
            "dirId": _roxy_id(profile_id),
            "args": [],
            # Roxy opens asynchronously. The connection_info reconciliation
            # below handles the short race without forcing a second window.
            "forceOpen": False,
            "headless": bool(self.config.get("headless", False)),
        }
        payload = self.request("POST", str(self.config.get("open_path") or "/browser/open"), body=body)
        opened = self._connection_result(profile_id, payload)
        if opened is not None:
            return opened
        # Some Roxy versions return success before the CDP endpoint exists;
        # reconcile the same dirId instead of creating another Profile/window.
        for _attempt in range(3):
            try:
                opened = self.connection_info(profile_id)
            except Exception:
                opened = None
            if opened is not None:
                return opened
            time.sleep(0.5)
        raise FreeRegisterError(
            "free_roxy_open",
            "打开 RoxyBrowser 环境",
            "RoxyBrowser 打开成功但未返回 Selenium/CDP 连接地址，connection_info 也未就绪",
            retryable=True,
        )

    def close_profile(self, profile_id: str) -> None:
        body = {"workspaceId": _roxy_id(self.config.get("workspace_id")), "dirId": _roxy_id(profile_id)}
        self.request("POST", str(self.config.get("close_path") or "/browser/close"), body=body)

    def delete_profile(self, profile_id: str) -> None:
        body = {"workspaceId": _roxy_id(self.config.get("workspace_id")), "dirIds": [_roxy_id(profile_id)]}
        self.request("POST", str(self.config.get("delete_path") or "/browser/delete"), body=body)

    def cleanup(self, opened: RoxyOpenResult | None) -> None:
        if opened is None or not opened.profile_id or bool(self.config.get("keep_browser_open", False)):
            return
        try:
            self.close_profile(opened.profile_id)
        except Exception as exc:
            self._log(f"[清理 RoxyBrowser 环境/free_roxy_cleanup] 关闭失败（{type(exc).__name__}）", "warn")
        if bool(self.config.get("one_profile_per_account", True)) and bool(self.config.get("delete_profile_after_run", True)) and opened.created_by_run:
            try:
                self.delete_profile(opened.profile_id)
            except Exception as exc:
                self._log(f"[清理 RoxyBrowser 环境/free_roxy_cleanup] 删除失败（{type(exc).__name__}）", "warn")


class Humanizer:
    DELAYS = {
        "navigate": (1.2, 3.2), "otp_input": (2.5, 8.0), "form": (1.8, 5.0),
        "post_auth": (1.5, 4.0), "job_stagger": (0.4, 1.8), "click": (0.15, 0.85),
        "keystroke": (0.035, 0.18), "page_warmup": (0.7, 2.2),
    }

    def __init__(self, config: Mapping[str, Any]) -> None:
        self.enabled = bool(config.get("humanize_delay", True))
        self.actions = bool(config.get("humanize_browser_actions", True))
        self.factor = max(0.1, float(config.get("humanize_factor") or 1.0))

    def delay(self, kind: str) -> float:
        if not self.enabled:
            return 0.0
        low, high = self.DELAYS.get(kind, (0.4, 1.2))
        seconds = random.uniform(low, high) * self.factor
        time.sleep(seconds)
        return seconds


class RoxyRegistrationRunner:
    def __init__(self, *, registration_ip_probe: Callable[[Any, Mapping[str, Any]], str] | None = None) -> None:
        self.registration_ip_probe = registration_ip_probe

    @staticmethod
    def preflight(config: Mapping[str, Any]) -> dict[str, Any]:
        roxy = config.get("roxybrowser") if isinstance(config.get("roxybrowser"), Mapping) else {}
        missing = [label for key, label in (("workspace_id", "Workspace"), ("project_id", "Project")) if not str(roxy.get(key) or "").strip()]
        if missing:
            raise FreeRegisterError("free_roxy_preflight", "RoxyBrowser 预检", f"请先配置 RoxyBrowser {'、'.join(missing)}", retryable=False)
        if not bool(roxy.get("one_profile_per_account", True)):
            raise FreeRegisterError("free_roxy_preflight", "RoxyBrowser 预检", "RoxyBrowser 必须启用一号一 Profile", retryable=False)
        try:
            import selenium  # noqa: F401
        except ImportError as exc:
            raise FreeRegisterError("free_roxy_preflight", "RoxyBrowser 预检", "当前运行环境缺少 Selenium，无法启动 RoxyBrowser", retryable=False) from exc
        return {"driver": "roxybrowser", "selenium": "available"}

    @staticmethod
    def _driver(opened: RoxyOpenResult):
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        from selenium.webdriver.remote.webdriver import WebDriver as RemoteWebDriver

        options = Options()
        options.page_load_strategy = "eager"
        if opened.debugger_address:
            options.add_experimental_option("debuggerAddress", opened.debugger_address)
            driver = webdriver.Chrome(options=options)
        elif opened.webdriver_url:
            driver = RemoteWebDriver(command_executor=opened.webdriver_url, options=options)
        else:
            raise FreeRegisterError("free_roxy_connect", "连接 RoxyBrowser", "缺少 Selenium 连接地址")
        script = """
        Object.defineProperty(Navigator.prototype, 'webdriver', {get: () => undefined});
        if (!window.chrome) window.chrome = {}; if (!window.chrome.runtime) window.chrome.runtime = {};
        """
        try:
            driver.execute_cdp_cmd("Page.addScriptToEvaluateOnNewDocument", {"source": script})
        except Exception:
            pass
        return driver

    @staticmethod
    def _find(driver: Any, selectors: list[str], timeout: int):
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

    @staticmethod
    def _click(driver: Any, element: Any, human: Humanizer) -> None:
        try:
            driver.execute_script("arguments[0].scrollIntoView({block:'center'});", element)
        except Exception:
            pass
        human.delay("click")
        try:
            element.click()
        except Exception:
            driver.execute_script("arguments[0].click();", element)

    @staticmethod
    def _type(element: Any, value: str, human: Humanizer) -> None:
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

    @staticmethod
    def _submit(driver: Any, human: Humanizer) -> None:
        button = RoxyRegistrationRunner._find(
            driver,
            ["button[type='submit']", "input[type='submit']", "button[data-testid*='continue']", "button[name='action']"],
            15,
        )
        RoxyRegistrationRunner._click(driver, button, human)

    @staticmethod
    def _fill_otp(driver: Any, code: str, human: Humanizer) -> None:
        from selenium.webdriver.common.by import By

        fields = [element for element in driver.find_elements(By.CSS_SELECTOR, "input[inputmode='numeric'], input[autocomplete='one-time-code'], input[name*='code'], input[name*='otp']") if element.is_displayed()]
        if not fields:
            raise FreeRegisterError("free_email_otp_validate", "验证 Free 邮箱验证码", "RoxyBrowser 页面未找到验证码输入框")
        human.delay("otp_input")
        if len(fields) >= len(code) and all(int(element.get_attribute("maxlength") or 1) == 1 for element in fields[:len(code)]):
            for field, character in zip(fields, code):
                field.send_keys(character)
                human.delay("keystroke")
        else:
            RoxyRegistrationRunner._type(fields[0], code, human)
        RoxyRegistrationRunner._submit(driver, human)

    @staticmethod
    def _complete_profile(driver: Any, human: Humanizer) -> None:
        url = str(getattr(driver, "current_url", "") or "").lower()
        if not any(value in url for value in ("about-you", "profile", "create-account")):
            return
        name = random_display_name()
        birthday = random_birthdate()
        try:
            field = RoxyRegistrationRunner._find(driver, ["input[name='name']", "input[name='full_name']", "input[autocomplete='name']"], 8)
            RoxyRegistrationRunner._type(field, name, human)
        except Exception:
            pass
        driver.execute_script("""
        const birthday=String(arguments[0]), [year,month,day]=birthday.split('-');
        const set=(el,value)=>{if(!el)return false; const p=HTMLInputElement.prototype; const s=Object.getOwnPropertyDescriptor(p,'value')?.set; if(s)s.call(el,value);else el.value=value; el.dispatchEvent(new Event('input',{bubbles:true}));el.dispatchEvent(new Event('change',{bubbles:true}));return true;};
        set(document.querySelector('input[type=date],input[name=birthday],input[name=birthdate]'),birthday);
        set(document.querySelector('input[name=year],input[id*=year]'),year);
        set(document.querySelector('input[name=month],input[id*=month]'),String(Number(month)));
        set(document.querySelector('input[name=day],input[id*=day]'),String(Number(day)));
        """, birthday)
        human.delay("form")
        try:
            RoxyRegistrationRunner._submit(driver, human)
        except Exception:
            pass

    @staticmethod
    def _session(driver: Any, timeout: int) -> dict[str, Any]:
        return extract_session(driver, timeout)

    @staticmethod
    def _browser_ip(driver: Any, probe_url: str, timeout: int) -> str:
        driver.set_page_load_timeout(timeout)
        driver.get(probe_url)
        text = str(driver.find_element("tag name", "body").text or "").strip()
        match = re.search(r"[0-9a-fA-F:.]{3,64}", text)
        if not match:
            raise FreeRegisterError("free_roxy_ip_verify", "校验 RoxyBrowser 出口 IP", "RoxyBrowser 出口 IP 响应格式无效")
        return match.group(0)

    @staticmethod
    def _safe_page_location(driver: Any) -> str:
        return safe_page_location(driver)

    @staticmethod
    def _open_signup_page(driver: Any, email: str, timeout: int) -> None:
        return open_signup_page(driver, email, timeout)

    @staticmethod
    def _is_email_verification_page(driver: Any) -> bool:
        return is_email_verification_page(driver)

    @staticmethod
    def _totp(secret: str) -> str:
        normalized = str(secret or "").replace(" ", "").upper()
        padding = "=" * ((8 - len(normalized) % 8) % 8)
        key = base64.b32decode(normalized + padding, casefold=True)
        counter = int(time.time()) // 30
        digest = hmac.new(key, counter.to_bytes(8, "big"), hashlib.sha1).digest()
        offset = digest[-1] & 0x0F
        return f"{((int.from_bytes(digest[offset:offset + 4], 'big') & 0x7fffffff) % 1_000_000):06d}"

    @staticmethod
    def _plan(driver: Any, token: str) -> tuple[str, bool]:
        script = """
        const token=arguments[0], done=arguments[arguments.length - 1];
        Promise.all([
          fetch('/backend-api/accounts/check/v4-2023-04-27',{headers:{authorization:'Bearer '+token}}).then(r=>r.json()),
          fetch('/backend-api/aip/first-party/eligibility',{headers:{authorization:'Bearer '+token}}).then(r=>r.json()).catch(()=>({}))
        ]).then(v=>done({ok:true,accounts:v[0],eligibility:v[1]})).catch(e=>done({ok:false,error:String(e)}));
        """
        result = driver.execute_async_script(script, token) or {}
        if not result.get("ok"):
            raise FreeRegisterError("free_plan_check", "查询 Free 套餐资格", "RoxyBrowser 套餐查询失败")
        accounts = result.get("accounts") if isinstance(result.get("accounts"), Mapping) else {}
        plan = "free"
        values = accounts.get("accounts") if isinstance(accounts.get("accounts"), Mapping) else {}
        for item in values.values() if isinstance(values, Mapping) else []:
            if isinstance(item, Mapping):
                account = item.get("account") if isinstance(item.get("account"), Mapping) else item
                candidate = str(account.get("plan_type") or account.get("planType") or "").strip()
                if candidate:
                    plan = candidate
                    break
        eligible = plus_trial_from_accounts(accounts) or plus_trial_from_accounts(result.get("eligibility"))
        return plan, eligible

    @staticmethod
    def _plan_details(driver: Any, token: str) -> dict[str, Any]:
        plan, eligible = RoxyRegistrationRunner._plan(driver, token)
        return {
            "plan_check_status": "success",
            "plan_type": plan,
            "subscription_plan": plan,
            "has_active_subscription": plan not in {"", "free"},
            "plus_trial_eligible": eligible,
            "plan_checked_at": time.time(),
        }

    def _setup_2fa(self, driver: Any, task: Mapping[str, Any], token: str, otp: MailboxUrlOtpProvider, human: Humanizer, stage: Callable[[str, str], None]) -> str:
        task_id = str(task.get("task_id") or "")
        stage(task_id, "free_twofa_enroll")
        otp.mark_sent()
        signin = driver.execute_async_script("""
        const email=arguments[0], done=arguments[arguments.length - 1];
        fetch('/api/auth/csrf',{credentials:'include'}).then(r=>r.json()).then(csrf=>{
          const q=new URLSearchParams({connection:'password',login_hint:email,reauth:'password',max_age:'0'});
          const body=new URLSearchParams({callbackUrl:'https://chatgpt.com/?action=enable&factor=totp',csrfToken:csrf.csrfToken,json:'true'});
          return fetch('/api/auth/signin/openai?'+q,{method:'POST',credentials:'include',headers:{'content-type':'application/x-www-form-urlencoded'},body});
        }).then(r=>r.json()).then(v=>done({ok:true,url:v.url})).catch(e=>done({ok:false,error:String(e)}));
        """, str(task.get("email") or "")) or {}
        if not signin.get("ok") or not signin.get("url"):
            raise FreeRegisterError("free_twofa_enroll", "注册 Free 账号 2FA", "RoxyBrowser 未能发起 2FA 重认证")
        driver.get(str(signin["url"]))
        code = otp.wait_code(str(task.get("email") or ""))
        self._fill_otp(driver, code, human)
        refreshed = self._session(driver, 90)
        new_token = str(refreshed.get("accessToken") or token)
        enrolled = driver.execute_async_script("""
        const token=arguments[0], done=arguments[arguments.length - 1]; fetch('https://chatgpt.com/backend-api/accounts/mfa/enroll',{
          method:'POST',credentials:'include',headers:{authorization:'Bearer '+token,'content-type':'application/json'},body:JSON.stringify({factor_type:'totp'})
        }).then(async r=>done({ok:r.ok,status:r.status,value:await r.json().catch(()=>({}))})).catch(e=>done({ok:false,error:String(e)}));
        """, new_token) or {}
        data = enrolled.get("value") if isinstance(enrolled.get("value"), Mapping) else {}
        secret = str(data.get("secret") or "")
        session_id = str(data.get("session_id") or "")
        if not enrolled.get("ok") or not secret or not session_id:
            status = enrolled.get("status") or None
            raise FreeRegisterError(
                "free_twofa_enroll", "注册 Free 账号 2FA",
                f"RoxyBrowser 2FA enrollment 失败（HTTP {status or '-'}）",
                provider_status=status,
            )
        stage(task_id, "free_twofa_activate")
        activated = driver.execute_async_script("""
        const token=arguments[0], code=arguments[1], sid=arguments[2], done=arguments[arguments.length - 1]; fetch('https://chatgpt.com/backend-api/accounts/mfa/user/activate_enrollment',{
          method:'POST',credentials:'include',headers:{authorization:'Bearer '+token,'content-type':'application/json'},body:JSON.stringify({code,factor_type:'totp',session_id:sid})
        }).then(async r=>done({ok:r.ok,status:r.status,value:await r.json().catch(()=>({}))})).catch(e=>done({ok:false,error:String(e)}));
        """, new_token, self._totp(secret), session_id) or {}
        value = activated.get("value") if isinstance(activated.get("value"), Mapping) else {}
        if not activated.get("ok") or not value.get("success"):
            status = activated.get("status") or None
            raise FreeRegisterError(
                "free_twofa_activate", "激活 Free 账号 2FA",
                f"RoxyBrowser 2FA 激活失败（HTTP {status or '-'}）",
                provider_status=status,
            )
        return secret

    def __call__(self, task: Mapping[str, Any], config: Mapping[str, Any], stop_event: Any, stage: Callable[[str, str], None], log: Callable[[str, str], None], *, twofa_retry: bool = False) -> Mapping[str, Any]:
        if twofa_retry:
            raise FreeRegisterError("free_twofa_retry", "重试 Free 账号 2FA", "RoxyBrowser 2FA 重试需要重新登录，请重新运行该邮箱", retryable=False)
        roxy = dict(config.get("roxybrowser") or {})
        human = Humanizer(roxy)
        human.delay("job_stagger")
        client = RoxyBrowserClient(roxy, log_fn=log)
        opened: RoxyOpenResult | None = None
        driver: Any | None = None
        task_id = str(task.get("task_id") or "")
        otp = MailboxUrlOtpProvider(
            str(task.get("mailbox_url") or ""), str(task.get("proxy") or ""),
            timeout=int(config.get("email_code_timeout") or 90), log_fn=log, task_id=task_id, stage_fn=stage,
        )
        try:
            if stop_event.is_set():
                raise FreeRegisterError("free_run_stop", "停止 Free 注册", "任务在创建 RoxyBrowser 环境前已停止", retryable=False)
            stage(task_id, "free_roxy_create")
            profile_id = client.create_profile(str(task.get("proxy") or ""))
            # Keep ownership as soon as creation succeeds so an open/connect
            # failure still closes and deletes this run's temporary Profile.
            opened = RoxyOpenResult(profile_id, {}, created_by_run=True)
            stage(task_id, "free_roxy_open")
            opened = client.open_profile(profile_id)
            stage(task_id, "free_roxy_connect")
            driver = self._driver(opened)
            driver.set_script_timeout(max(20, int(roxy.get("selenium_timeout") or 90)))
            stage(task_id, "free_roxy_ip_verify")
            registration_ip = self._browser_ip(driver, str(config.get("proxy_probe_url") or "https://api.ipify.org"), int(roxy.get("selenium_timeout") or 90))
            expected = str(task.get("expected_exit_ip") or task.get("exit_ip") or "")
            if registration_ip != expected:
                raise FreeRegisterError("free_roxy_ip_verify", "校验 RoxyBrowser 出口 IP", "RoxyBrowser 实际出口 IP 与任务预绑定出口不一致", retryable=False)
            stage(task_id, "free_roxy_signup_bootstrap")
            otp.prepare()
            self._open_signup_page(driver, str(task.get("email") or ""), int(roxy.get("selenium_timeout") or 90))
            human.delay("page_warmup")
            try:
                signup = self._find(driver, ["a[href*='signup']", "button[data-testid*='signup']"], 5)
                self._click(driver, signup, human)
            except Exception:
                pass
            email_already_submitted = self._is_email_verification_page(driver)
            if email_already_submitted:
                log("认证页已接受注册邮箱，直接进入邮箱验证码阶段", "info")
                otp.mark_sent()
            else:
                stage(task_id, "free_roxy_signup_email")
                try:
                    email_field = self._find(driver, ["input[type='email']", "input[name='email']", "input[autocomplete='email']", "input[name='username']"], 45)
                    self._type(email_field, str(task.get("email") or ""), human)
                except Exception as exc:
                    if self._is_email_verification_page(driver):
                        email_already_submitted = True
                        log("等待邮箱输入框期间认证页已进入邮箱验证码阶段", "info")
                        otp.mark_sent()
                    else:
                        try:
                            body = str(driver.find_element("tag name", "body").text or "").lower()
                        except Exception:
                            body = ""
                        challenge = any(token in body for token in ("cloudflare", "verify you are human", "安全验证", "challenge"))
                        node_code = "free_roxy_challenge" if challenge else "free_roxy_signup_email"
                        node_label = "等待注册页安全验证" if challenge else "填写 Free 注册邮箱"
                        message = "注册页出现安全验证，邮箱输入框未开放" if challenge else f"45 秒内未找到可用邮箱输入框（{self._safe_page_location(driver)}）"
                        raise FreeRegisterError(node_code, node_label, message, error_code=f"{node_code}_timeout") from exc
                if not email_already_submitted:
                    otp.mark_sent()
                    stage(task_id, "free_roxy_signup_email_submit")
                    try:
                        self._submit(driver, human)
                    except Exception as exc:
                        raise FreeRegisterError(
                            "free_roxy_signup_email_submit", "提交 Free 注册邮箱",
                            f"注册邮箱提交失败（{type(exc).__name__}，{self._safe_page_location(driver)}）",
                            error_code="free_roxy_signup_email_submit_timeout" if type(exc).__name__ == "TimeoutException" else "free_roxy_signup_email_submit_failed",
                        ) from exc
                    human.delay("navigate")
            if not self._is_email_verification_page(driver):
                stage(task_id, "free_roxy_signup_password")
                try:
                    password_field = self._find(driver, ["input[type='password']", "input[name='password']", "input[autocomplete='new-password']"], 8)
                    current = str(driver.current_url or "").lower()
                    if "/log-in/password" in current:
                        raise FreeRegisterError("free_roxy_signup", "RoxyBrowser 页面注册", "邮箱已进入登录密码页，不能作为新账号注册", retryable=False)
                    self._type(password_field, FIXED_PASSWORD, human)
                    otp.mark_sent()
                    try:
                        self._submit(driver, human)
                    except Exception as exc:
                        raise FreeRegisterError(
                            "free_roxy_signup_password", "提交 Free 注册密码",
                            f"注册密码提交失败（{type(exc).__name__}，{self._safe_page_location(driver)}）",
                            error_code="free_roxy_signup_password_submit_timeout" if type(exc).__name__ == "TimeoutException" else "free_roxy_signup_password_submit_failed",
                        ) from exc
                except FreeRegisterError:
                    raise
                except Exception:
                    pass
            stage(task_id, "free_email_otp_wait")
            code = otp.wait_code(str(task.get("email") or ""))
            stage(task_id, "free_email_otp_validate")
            self._fill_otp(driver, code, human)
            human.delay("navigate")
            self._complete_profile(driver, human)
            if "chatgpt.com" not in str(driver.current_url or ""):
                driver.get("https://chatgpt.com/")
            session = self._session(driver, 120)
            token = session_token(session)
            stage(task_id, "free_plan_check")
            try:
                plan_details = self._plan_details(driver, token)
            except FreeRegisterError as exc:
                plan_details = {
                    "plan_check_status": "failed",
                    "plan_error_code": str(getattr(exc, "error_code", "free_plan_check_failed")),
                    "plan_http_status": getattr(exc, "provider_status", None),
                    "plan_type": "",
                    "plus_trial_eligible": False,
                }
            twofa_status = "disabled"
            totp_secret = ""
            twofa_error = ""
            twofa_failure: dict[str, Any] | None = None
            if bool(config.get("auto_set_2fa", True)):
                try:
                    totp_secret = self._setup_2fa(driver, task, token, otp, human, stage)
                    twofa_status = "enabled"
                except FreeRegisterError as exc:
                    twofa_status = "pending"
                    twofa_error = safe_log_message(exc)
                    twofa_failure = {
                        "node_code": str(exc.node_code or "free_twofa_activate"),
                        "node_label": str(exc.node_label or "激活 Free 账号 2FA"),
                        "error_code": str(exc.error_code or "free_twofa_failed"),
                        "public_message": f"{exc.node_label} [{exc.node_label}/{exc.node_code}]：{safe_log_message(exc)}",
                        "technical_summary": safe_log_message(exc),
                        "retryable": bool(exc.retryable),
                    }
                    if exc.provider_status is not None:
                        twofa_failure["http_status"] = exc.provider_status
                except Exception as exc:
                    twofa_status = "pending"
                    twofa_error = f"2FA 设置失败（{type(exc).__name__}）"
                    twofa_failure = {
                        "node_code": "free_twofa_activate",
                        "node_label": "激活 Free 账号 2FA",
                        "error_code": "free_twofa_activate_failed",
                        "public_message": f"激活 Free 账号 2FA [激活 Free 账号 2FA/free_twofa_activate]：{safe_log_message(exc)}",
                        "technical_summary": safe_log_message(exc),
                        "retryable": True,
                    }
            dwell_min = int(roxy.get("post_registration_dwell_min") or 18)
            dwell_max = max(dwell_min, int(roxy.get("post_registration_dwell_max") or 45))
            if dwell_max > 0:
                time.sleep(random.uniform(dwell_min, dwell_max))
            result = {
                "driver": "roxybrowser", "access_token": token, "password": FIXED_PASSWORD,
                **plan_details, "twofa_status": twofa_status,
                "twofa_error": twofa_error, "registration_ip": registration_ip,
                "expected_exit_ip": expected, "profile_summary": f"Roxy#{profile_id}",
            }
            if twofa_failure:
                result["twofa_failure"] = twofa_failure
            if totp_secret:
                result["totp_secret"] = totp_secret
                result["credential_line"] = f"{task.get('email')}----{FIXED_PASSWORD}----{totp_secret}"
            return result
        except FreeRegisterError:
            raise
        except Exception as exc:
            raise FreeRegisterError("free_roxy_signup", "RoxyBrowser 页面注册", f"RoxyBrowser 注册异常（{type(exc).__name__}）") from exc
        finally:
            if driver is not None and not bool(roxy.get("keep_browser_open", False)):
                try:
                    driver.quit()
                except Exception:
                    pass
            # Cleanup is diagnostic only; do not overwrite the terminal stage
            # (for example free_roxy_connect) with a cleanup stage.
            log(f"[{task_id}/清理 RoxyBrowser 环境/free_roxy_cleanup] 开始", "info")
            try:
                client.cleanup(opened)
            except Exception as exc:
                log(f"[{task_id}/清理 RoxyBrowser 环境/free_roxy_cleanup] 清理异常（{type(exc).__name__}）", "warn")


__all__ = ["RoxyBrowserClient", "RoxyOpenResult", "RoxyRegistrationRunner", "proxy_to_roxy_info"]
