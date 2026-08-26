"""RoxyBrowser API and Selenium registration driver for isolated Free runs."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import random
import re
import time
from typing import Any, Callable, Mapping

try:
    from .free_roxy_client import (
        RoxyBrowserClient,
        RoxyOpenResult,
        _dig,
        _first,
        _roxy_id,
        proxy_to_roxy_info,
    )
    from .free_mailbox_otp import MailboxUrlOtpProvider, build_free_mailbox_otp_provider
    from .free_roxy_email_adapter import submit_registration_email
    from .free_proxy_store import _extract_probe_ip as extract_probe_ip, normalize_probe_url
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
    from .free_roxy_signup import (
        is_email_verification_page,
        open_signup_page,
        safe_page_location,
        warmup_login_page,
    )
    from .free_roxy_driver import (
        build_driver,
        click_element,
        driver_source,
        find_element,
        submit_form,
        type_element,
    )
    from .free_roxy_page_flow import (
        click_resend_email_otp,
        classify_page,
        install_password_submit_probe,
        native_password_submit,
        page_snapshot,
        password_form_targets,
        read_password_submit_probe,
        switch_login_to_email_code,
        wait_for_security_clear,
        wait_after_email_submit,
        wait_after_otp_submit,
        wait_after_passwordless_switch,
        wait_after_signup_password_submit,
        wait_for_home,
    )
    from .free_roxy_otp_flow import (
        fill_otp as fill_roxy_otp,
        follow_oauth_continue,
        reload_otp_page,
        reopen_email_otp_flow,
        run_otp_attempts,
        select_active_auth_window,
        wait_after_otp_submit as wait_after_roxy_otp_submit,
        wait_for_continue_url,
    )
    from .free_roxy_session import extract_session, session_token
    from .free_account_service import finalize_registration_result
    from .free_roxy_profile import complete_profile_page
    from .free_roxy_twofa import setup_twofa
    from .free_roxy_lifecycle import (
        MANAGED_WINDOW_PREFIX,
        MANAGED_WINDOW_REMARK,
        RoxyCleanupStore,
        RoxyLifecycle,
    )
except ImportError:
    from free_roxy_client import (  # type: ignore[no-redef]
        RoxyBrowserClient,
        RoxyOpenResult,
        _dig,
        _first,
        _roxy_id,
        proxy_to_roxy_info,
    )
    from free_mailbox_otp import MailboxUrlOtpProvider, build_free_mailbox_otp_provider  # type: ignore[no-redef]
    from free_roxy_email_adapter import submit_registration_email  # type: ignore[no-redef]
    from free_proxy_store import _extract_probe_ip as extract_probe_ip, normalize_probe_url  # type: ignore[no-redef]
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
    from free_roxy_signup import (  # type: ignore[no-redef]
        is_email_verification_page,
        open_signup_page,
        safe_page_location,
        warmup_login_page,
    )
    from free_roxy_driver import (  # type: ignore[no-redef]
        build_driver,
        click_element,
        driver_source,
        find_element,
        submit_form,
        type_element,
    )
    from free_roxy_page_flow import (  # type: ignore[no-redef]
        click_resend_email_otp,
        classify_page,
        install_password_submit_probe,
        native_password_submit,
        page_snapshot,
        password_form_targets,
        read_password_submit_probe,
        switch_login_to_email_code,
        wait_for_security_clear,
        wait_after_email_submit,
        wait_after_otp_submit,
        wait_after_passwordless_switch,
        wait_after_signup_password_submit,
        wait_for_home,
    )
    from free_roxy_otp_flow import (  # type: ignore[no-redef]
        fill_otp as fill_roxy_otp,
        follow_oauth_continue,
        reload_otp_page,
        reopen_email_otp_flow,
        run_otp_attempts,
        select_active_auth_window,
        wait_after_otp_submit as wait_after_roxy_otp_submit,
        wait_for_continue_url,
    )
    from free_roxy_session import extract_session, session_token  # type: ignore[no-redef]
    from free_account_service import finalize_registration_result  # type: ignore[no-redef]
    from free_roxy_profile import complete_profile_page  # type: ignore[no-redef]
    from free_roxy_twofa import setup_twofa  # type: ignore[no-redef]
    from free_roxy_lifecycle import (  # type: ignore[no-redef]
        MANAGED_WINDOW_PREFIX,
        MANAGED_WINDOW_REMARK,
        RoxyCleanupStore,
        RoxyLifecycle,
    )


def _http_status(value: Any) -> int:
    try:
        status = int(value or 0)
    except (TypeError, ValueError):
        return 0
    return status if 100 <= status <= 599 else 0


def _provider_code(response: Mapping[str, Any], fallback: str) -> str:
    sources: list[Mapping[str, Any]] = [response]
    payload = response.get("payload")
    if isinstance(payload, Mapping):
        sources.append(payload)
        error = payload.get("error")
        if isinstance(error, Mapping):
            sources.append(error)
    for source in sources:
        for key in ("provider_code", "error_code", "code", "type"):
            value = source.get(key)
            if value not in (None, "", 0, "0") and not isinstance(value, (Mapping, list, tuple)):
                return safe_log_message(value)[:120]
    return fallback


def _structured_failure(error: BaseException, *, action_hint: str) -> dict[str, Any]:
    node_code = str(getattr(error, "node_code", "") or "free_plan_check")
    node_label = str(getattr(error, "node_label", "") or "查询 Free 套餐资格")
    technical = safe_log_message(error) or "服务端未返回错误详情"
    failure: dict[str, Any] = {
        "node_code": node_code,
        "node_label": node_label,
        "error_code": str(getattr(error, "error_code", "") or f"{node_code}_failed"),
        "public_message": f"{node_label} [{node_label}/{node_code}]：{technical}",
        "technical_summary": technical,
        "retryable": bool(getattr(error, "retryable", True)),
        "action_hint": safe_log_message(getattr(error, "action_hint", "") or action_hint)[:300],
    }
    status = _http_status(getattr(error, "provider_status", None))
    if status:
        failure["http_status"] = status
    provider_code = safe_log_message(getattr(error, "provider_code", ""))[:120]
    if provider_code:
        failure["provider_code"] = provider_code
    content_type = clean(getattr(error, "content_type", ""), 120)
    if content_type:
        failure["content_type"] = content_type
    return failure



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
    def __init__(
        self,
        *,
        registration_ip_probe: Callable[[Any, Mapping[str, Any]], str] | None = None,
        lifecycle_store_path: str | None = None,
    ) -> None:
        self.registration_ip_probe = registration_ip_probe
        self.lifecycle_store_path = lifecycle_store_path or ""

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
        return build_driver(opened)

    @staticmethod
    def _driver_source(opened: RoxyOpenResult) -> str:
        return driver_source(opened)

    @staticmethod
    def _find(driver: Any, selectors: list[str], timeout: int):
        return find_element(driver, selectors, timeout)

    @staticmethod
    def _click(driver: Any, element: Any, human: Humanizer) -> None:
        click_element(driver, element, human)

    @staticmethod
    def _type(element: Any, value: str, human: Humanizer) -> None:
        type_element(element, value, human)

    @staticmethod
    def _submit(driver: Any, human: Humanizer) -> None:
        submit_form(driver, human, RoxyRegistrationRunner._find, RoxyRegistrationRunner._click)

    @staticmethod
    def _fill_otp(driver: Any, code: str, human: Humanizer) -> Mapping[str, Any]:
        return fill_roxy_otp(driver, code, human)

    _select_active_auth_window = staticmethod(select_active_auth_window)

    _page_snapshot = staticmethod(page_snapshot)
    _classify_page = staticmethod(classify_page)
    _wait_after_otp_submit = staticmethod(wait_after_roxy_otp_submit)
    _wait_for_home = staticmethod(wait_for_home)
    _switch_login_to_email_code = staticmethod(switch_login_to_email_code)
    _wait_after_email_submit = staticmethod(wait_after_email_submit)
    _wait_after_passwordless_switch = staticmethod(wait_after_passwordless_switch)
    _password_form_targets = staticmethod(password_form_targets)
    _install_password_submit_probe = staticmethod(install_password_submit_probe)
    _read_password_submit_probe = staticmethod(read_password_submit_probe)
    _native_password_submit = staticmethod(native_password_submit)
    _wait_after_signup_password_submit = staticmethod(wait_after_signup_password_submit)
    _click_resend_email_otp = staticmethod(click_resend_email_otp)
    _warmup_login_page = staticmethod(warmup_login_page)

    def _submit_registration_email(
        self,
        driver: Any,
        email: str,
        human: Humanizer,
        log: Callable[[str, str], None],
        timeout: int,
    ) -> str:
        return submit_registration_email(
            driver, email, human, log, timeout,
            classify=self._classify_page, wait_security=wait_for_security_clear,
            type_element=self._type, click_element=self._click,
            select_auth_window=self._select_active_auth_window, attempts=3,
        )

    def _submit_signup_password(
        self,
        driver: Any,
        human: Humanizer,
        log: Callable[[str, str], None],
    ) -> str:
        field, button = self._password_form_targets(driver)
        self._type(field, FIXED_PASSWORD, human)
        if str(field.get_attribute("value") or "") != FIXED_PASSWORD:
            raise FreeRegisterError(
                "free_roxy_signup_password", "提交 Free 注册密码",
                "注册密码输入框写入校验失败",
                error_code="free_roxy_signup_password_value_mismatch",
            )
        before_page = self._page_snapshot(driver)
        telemetry = self._install_password_submit_probe(driver, field, button)
        if telemetry.get("invalid"):
            raise FreeRegisterError(
                "free_roxy_signup_password", "提交 Free 注册密码",
                "注册密码表单未通过页面校验，未执行提交",
                error_code="free_roxy_signup_password_form_invalid",
                retryable=False,
            )
        if telemetry.get("button_disabled") or str(telemetry.get("aria_disabled") or "").lower() == "true":
            raise FreeRegisterError(
                "free_roxy_signup_password", "提交 Free 注册密码",
                "注册密码提交按钮当前不可用，未执行重复提交",
                error_code="free_roxy_signup_password_button_disabled",
                retryable=False,
            )
        log(
            "注册密码表单已就绪"
            f"（password_length={len(FIXED_PASSWORD)}，button_type={telemetry.get('button_type') or 'unknown'}，"
            f"form_valid={not bool(telemetry.get('invalid'))}）",
            "info",
        )
        self._click(driver, button, human)
        after_click = self._read_password_submit_probe(driver)
        after_page = self._page_snapshot(driver)
        unchanged = (
            before_page.get("url") == after_page.get("url")
            and before_page.get("title") == after_page.get("title")
            and before_page.get("body") == after_page.get("body")
        )
        if not after_click.get("submit_observed") and unchanged:
            if self._native_password_submit(driver, field, button):
                log("首次点击未观察到提交事件且页面未变化，已执行一次原生表单提交兜底", "warn")
            else:
                raise FreeRegisterError(
                    "free_roxy_signup_password", "提交 Free 注册密码",
                    "首次点击未触发表单提交，原生表单提交兜底不可用",
                    error_code="free_roxy_signup_password_submit_not_observed",
                )
        log(
            "注册密码已提交一次，等待页面状态变化"
            f"（submit_observed={bool(after_click.get('submit_observed'))}，位置={safe_page_location(driver)}）",
            "info",
        )
        human.delay("navigate")
        return self._wait_after_signup_password_submit(driver, 45, log)

    def _wait_mailbox_code(
        self,
        otp: Any,
        email: str,
        stage_code: str,
        driver: Any,
        human: Humanizer,
        log: Callable[[str, str], None],
    ) -> str:
        def resend() -> None:
            self._click_resend_email_otp(driver, human)
            log(f"邮箱验证码尚未到达，已在同一验证码页受控重发一次（位置={safe_page_location(driver)}）", "warn")

        try:
            return otp.wait_code(
                email,
                stage_code,
                resend_fn=resend,
                resend_after_seconds=12,
            )
        except TypeError as exc:
            if "unexpected keyword" not in str(exc):
                raise
            return otp.wait_code(email, stage_code)

    @staticmethod
    def _complete_profile(driver: Any, human: Humanizer, log: Callable[[str, str], None] | None = None) -> bool:
        if RoxyRegistrationRunner._classify_page(driver) != "profile":
            return False
        name = random_display_name()
        birthday = random_birthdate()
        if callable(log):
            log(f"识别到资料页，填写随机姓名和生日（{safe_page_location(driver)}）", "info")
        return complete_profile_page(
            driver,
            human,
            name,
            birthday,
            timeout=60,
            log=log,
            select_auth_window=RoxyRegistrationRunner._select_active_auth_window,
        )

    @staticmethod
    def _session(driver: Any, timeout: int, log: Callable[[str, str], None] | None = None) -> dict[str, Any]:
        return extract_session(driver, timeout, log_fn=log)

    @staticmethod
    def _browser_ip(driver: Any, probe_url: str, timeout: int) -> str:
        driver.set_page_load_timeout(timeout)
        driver.get(normalize_probe_url(probe_url))
        text = str(driver.find_element("tag name", "body").text or "").strip()
        try:
            return extract_probe_ip(text)
        except ValueError:
            raise FreeRegisterError("proxy_connect_failed", "代理连接失败", "代理连通性探测响应格式无效")

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
    def _plan(driver: Any, token: str) -> tuple[str, bool, dict[str, Any]]:
        script = """
        const token=arguments[0], done=arguments[arguments.length - 1];
        const read=async path=>{
          const response=await fetch(path,{credentials:'include',headers:{authorization:'Bearer '+token,accept:'application/json'}});
          const contentType=String(response.headers.get('content-type')||'');
          const payload=await response.json().catch(()=>null);
          return {status:response.status||0,content_type:contentType,
            payload:payload&&typeof payload==='object'?payload:{},json:Boolean(payload&&typeof payload==='object')};
        };
        Promise.all([
          read('/backend-api/accounts/check/v4-2023-04-27'),
          read('/backend-api/aip/first-party/eligibility')
        ]).then(v=>done({ok:true,accounts:v[0],eligibility:v[1]})).catch(e=>done({ok:false,error:String(e).slice(0,120)}));
        """
        raw_result = driver.execute_async_script(script, token) or {}
        result = raw_result if isinstance(raw_result, Mapping) else {}
        if not result.get("ok"):
            raise FreeRegisterError(
                "free_plan_check", "查询 Free 套餐资格",
                "RoxyBrowser 套餐查询网络请求失败",
                error_code="free_plan_check_request_failed",
                provider_code="browser_fetch_failed",
                action_hint="保留已注册账号，稍后重新查询套餐状态",
            )
        accounts_response = result.get("accounts") if isinstance(result.get("accounts"), Mapping) else {}
        eligibility_response = result.get("eligibility") if isinstance(result.get("eligibility"), Mapping) else {}
        accounts_status = _http_status(accounts_response.get("status"))
        eligibility_status = _http_status(eligibility_response.get("status"))
        accounts_type = clean(accounts_response.get("content_type"), 80)
        eligibility_type = clean(eligibility_response.get("content_type"), 80)
        accounts = accounts_response.get("payload") if isinstance(accounts_response.get("payload"), Mapping) else {}
        eligibility = eligibility_response.get("payload") if isinstance(eligibility_response.get("payload"), Mapping) else {}
        account_plan = ""
        values = accounts.get("accounts") if isinstance(accounts.get("accounts"), Mapping) else {}
        for item in values.values() if isinstance(values, Mapping) else []:
            if isinstance(item, Mapping):
                account = item.get("account") if isinstance(item.get("account"), Mapping) else item
                candidate = str(account.get("plan_type") or account.get("planType") or "").strip()
                if candidate:
                    account_plan = candidate
                    break
        eligibility_ok = 200 <= eligibility_status < 300 and bool(eligibility_response.get("json"))
        eligible = plus_trial_from_accounts(accounts) or (eligibility_ok and plus_trial_from_accounts(eligibility))
        diagnostic = {
            "plan_accounts_http_status": accounts_status or None,
            "plan_accounts_content_type": accounts_type,
            "plan_eligibility_http_status": eligibility_status or None,
            "plan_eligibility_content_type": eligibility_type,
            "plan_eligibility_provider_code": _provider_code(
                eligibility_response,
                "" if eligibility_ok else "eligibility_response_invalid",
            ),
            "plan_eligibility_status": "success" if eligibility_ok else "failed",
        }
        if not 200 <= accounts_status < 300 or not accounts_response.get("json"):
            failure = FreeRegisterError(
                "free_plan_check", "查询 Free 套餐资格",
                f"账号套餐接口响应无效（HTTP {accounts_status or '-'}，类型 {accounts_type or '-'}）",
                error_code="free_plan_accounts_response_invalid",
                provider_status=accounts_status or None,
                provider_code=_provider_code(accounts_response, "accounts_response_invalid"),
                action_hint="保留已注册账号，稍后重新查询套餐状态",
                content_type=accounts_type,
            )
            failure.partial_plan_details = {
                "plan_type": account_plan,
                "subscription_plan": account_plan,
                "has_active_subscription": bool(account_plan and account_plan != "free"),
                "plus_trial_eligible": bool(eligible),
                **diagnostic,
            }
            raise failure
        return account_plan or "free", bool(eligible), diagnostic

    @staticmethod
    def _plan_details(driver: Any, token: str) -> dict[str, Any]:
        plan, eligible, diagnostic = RoxyRegistrationRunner._plan(driver, token)
        details = {
            "plan_check_status": "success",
            "plan_type": plan,
            "subscription_plan": plan,
            "has_active_subscription": plan not in {"", "free"},
            "plus_trial_eligible": eligible,
            "plan_checked_at": time.time(),
            **diagnostic,
        }
        if diagnostic.get("plan_eligibility_status") == "failed":
            failure = FreeRegisterError(
                "free_plan_check", "查询 Free 套餐资格",
                f"Plus 资格接口响应无效（HTTP {diagnostic.get('plan_eligibility_http_status') or '-'}，类型 {diagnostic.get('plan_eligibility_content_type') or '-'}）",
                error_code="free_plan_eligibility_response_invalid",
                provider_status=diagnostic.get("plan_eligibility_http_status"),
                provider_code=str(diagnostic.get("plan_eligibility_provider_code") or "eligibility_response_invalid"),
                action_hint="已保留账号套餐信息，稍后重新查询 Plus 资格",
                content_type=str(diagnostic.get("plan_eligibility_content_type") or ""),
            )
            plan_failure = _structured_failure(
                failure,
                action_hint="已保留账号套餐信息，稍后重新查询 Plus 资格",
            )
            details.update({
                # The account endpoint succeeded and its fields remain below,
                # but the combined package query is still a failed check so
                # the manager persists plan_failure as partial_success.
                "plan_check_status": "failed",
                "plan_error_code": plan_failure["error_code"],
                "plan_http_status": plan_failure.get("http_status"),
                "plan_failure": plan_failure,
            })
        return details

    def _setup_2fa(self, driver: Any, task: Mapping[str, Any], token: str, otp: MailboxUrlOtpProvider, human: Humanizer, stage: Callable[[str, str], None], token_sink: Callable[[str], None] | None = None) -> str:
        return setup_twofa(
            driver, task, token, otp, human, stage,
            session_fn=lambda current, timeout: self._session(current, timeout),
            fill_otp_fn=self._fill_otp,
            wait_after_otp_fn=self._wait_after_otp_submit,
            wait_home_fn=self._wait_for_home,
            totp_fn=self._totp,
            token_sink=token_sink,
        )
    def __call__(self, task: Mapping[str, Any], config: Mapping[str, Any], stop_event: Any, stage: Callable[[str, str], None], log: Callable[[str, str], None], *, twofa_retry: bool = False) -> Mapping[str, Any]:
        if twofa_retry:
            raise FreeRegisterError("free_twofa_retry", "重试 Free 账号 2FA", "RoxyBrowser 2FA 重试需要重新登录，请重新运行该邮箱", retryable=False)
        roxy = dict(config.get("roxybrowser") or {})
        lifecycle_store_path = str(getattr(self, "lifecycle_store_path", "") or "")
        if lifecycle_store_path and "lifecycle_store_path" not in roxy:
            roxy["lifecycle_store_path"] = lifecycle_store_path
        human = Humanizer(roxy)
        human.delay("job_stagger")
        client = RoxyBrowserClient(roxy, log_fn=log)
        lifecycle_store = RoxyCleanupStore(str(roxy.get("lifecycle_store_path"))) if roxy.get("lifecycle_store_path") else None
        lifecycle = RoxyLifecycle(
            client,
            lifecycle_store,
            log_fn=log,
            verify_timeout=float(roxy.get("cleanup_verify_timeout") or 8),
            verify_interval=float(roxy.get("cleanup_verify_interval") or 0.25),
            retries=int(roxy.get("api_retries") or 3),
        ) if lifecycle_store is not None else None
        opened: RoxyOpenResult | None = None
        driver: Any | None = None
        task_id = str(task.get("task_id") or "")
        active_stage = "free_roxy_signup"
        account_flow = "signup"
        registration_password_used = False

        def set_stage(code: str, legacy_code: str | None = None) -> None:
            nonlocal active_stage
            if legacy_code is not None:
                code = legacy_code
            active_stage = code
            stage(task_id, code)

        otp = build_free_mailbox_otp_provider(
            str(task.get("mailbox_url") or ""), str(task.get("proxy") or ""), config,
            log_fn=log, task_id=task_id, stage_fn=stage,
        )
        try:
            if stop_event.is_set():
                raise FreeRegisterError("free_run_stop", "停止 Free 注册", "任务在创建 RoxyBrowser 环境前已停止", retryable=False)
            set_stage("free_roxy_create")
            operation_started = time.monotonic()
            intent_id = f"{task.get('batch_id') or 'batch'}:{task_id or 'task'}"
            if lifecycle_store is not None:
                lifecycle_store.reserve_intent(
                    intent_id,
                    workspace_id=roxy.get("workspace_id"),
                    batch_id=task.get("batch_id"),
                    task_id=task_id,
                    window_name=f"{MANAGED_WINDOW_PREFIX}{(task_id or task.get('batch_id') or '')[:48]}",
                    window_remark=MANAGED_WINDOW_REMARK,
                )
            try:
                try:
                    profile_id = client.create_profile(
                        str(task.get("proxy") or ""),
                        batch_id=str(task.get("batch_id") or ""),
                        task_id=task_id,
                    )
                except TypeError as create_exc:
                    if "unexpected keyword argument" not in str(create_exc):
                        raise
                    profile_id = client.create_profile(str(task.get("proxy") or ""))
            except Exception:
                if lifecycle is not None:
                    try:
                        for row in client.find_owned_profiles(task_id=task_id, batch_id=str(task.get("batch_id") or "")):
                            owned_id = str(row.get("profile_id") or "")
                            if not owned_id:
                                continue
                            record = lifecycle_store.upsert(
                                owned_id,
                                workspace_id=row.get("workspace_id") or roxy.get("workspace_id"),
                                batch_id=task.get("batch_id"),
                                task_id=task_id,
                                window_name=row.get("window_name"),
                                window_remark=row.get("window_remark"),
                                state="orphaned",
                            )
                            if lifecycle.cleanup(record):
                                lifecycle_store.clear_intent(intent_id)
                                lifecycle_store.clear_intent(task_id)
                    except Exception as recovery_exc:
                        log(f"创建失败后的 Roxy 孤儿 Profile 回收失败（{type(recovery_exc).__name__}）", "warn")
                raise
            log(f"临时 Profile 创建成功，Profile={profile_id}，duration_ms={int((time.monotonic() - operation_started) * 1000)} outcome=success", "success")
            created_metadata = getattr(client, "last_created_metadata", {})
            if not isinstance(created_metadata, Mapping):
                created_metadata = {}
            if lifecycle_store is not None:
                lifecycle_store.clear_intent(intent_id)
                lifecycle_store.upsert(
                    profile_id,
                    workspace_id=roxy.get("workspace_id"),
                    batch_id=task.get("batch_id"),
                    task_id=task_id,
                    window_name=created_metadata.get("window_name"),
                    window_remark=created_metadata.get("window_remark"),
                    state="created",
                )
                if task_id:
                    lifecycle_store.clear_intent(task_id)
            opened = RoxyOpenResult(
                profile_id,
                {},
                created_by_run=True,
                workspace_id=str(roxy.get("workspace_id") or ""),
                window_name=str(created_metadata.get("window_name") or ""),
                window_remark=str(created_metadata.get("window_remark") or MANAGED_WINDOW_REMARK),
            )
            set_stage("free_roxy_open")
            operation_started = time.monotonic()
            opened = client.open_profile(profile_id)
            log(
                "Profile 打开成功"
                f"（headless={bool(opened.headless if opened.headless is not None else roxy.get('headless', True))}，"
                f"forceOpen=False，connection_reused={bool(opened.connection_reused)}，"
                f"driver_source={self._driver_source(opened)}，"
                f"Selenium/CDP={'存在' if opened.debugger_address or opened.webdriver_url else '缺失'}）"
                f"，duration_ms={int((time.monotonic() - operation_started) * 1000)} outcome=success",
                "success",
            )
            set_stage("free_roxy_connect")
            operation_started = time.monotonic()
            driver = self._driver(opened)
            driver.set_script_timeout(max(20, int(roxy.get("selenium_timeout") or 90)))
            self._select_active_auth_window(driver, log)
            log(f"Selenium 已连接同一 Profile，duration_ms={int((time.monotonic() - operation_started) * 1000)} outcome=success", "success")
            # Exit IP is an optional observation.  It is never compared with
            # a historical value and must not block the account flow or emit
            # a validation log when the probe endpoint is unavailable.
            registration_ip = ""
            try:
                registration_ip = self._browser_ip(
                    driver,
                    str(config.get("proxy_probe_url") or "https://api.ipify.org"),
                    int(roxy.get("selenium_timeout") or 90),
                )
            except Exception:
                registration_ip = ""
            set_stage("free_roxy_signup_bootstrap")
            otp.prepare()
            operation_started = time.monotonic()
            self._open_signup_page(driver, str(task.get("email") or ""), int(roxy.get("selenium_timeout") or 90))
            self._select_active_auth_window(driver, log)
            initial_state = wait_for_security_clear(driver, int(roxy.get("selenium_timeout") or 90), log)
            if initial_state == "security":
                raise FreeRegisterError(
                    "free_roxy_challenge", "等待注册页安全验证",
                    f"注册页安全验证在限定时间内未完成（{safe_page_location(driver)}）",
                    retryable=False,
                    error_code="free_roxy_security_challenge",
                )
            log(f"注册页初始化完成，页面={safe_page_location(driver)}，duration_ms={int((time.monotonic() - operation_started) * 1000)} outcome=success", "success")
            self._warmup_login_page(driver, human)
            email_already_submitted = self._is_email_verification_page(driver)
            auth_state = "otp" if email_already_submitted else ""
            if email_already_submitted:
                log("认证页已接受注册邮箱，直接进入邮箱验证码阶段", "info")
                otp.mark_sent()
            else:
                set_stage("free_roxy_signup_email")
                try:
                    set_stage("free_roxy_signup_email_submit")
                    auth_state = self._submit_registration_email(
                        driver,
                        str(task.get("email") or ""),
                        human,
                        log,
                        int(roxy.get("selenium_timeout") or 90),
                    )
                    log(f"注册邮箱提交后页面状态={auth_state}，页面={safe_page_location(driver)} outcome=success", "success")
                    if auth_state == "otp":
                        otp.mark_sent()
                except FreeRegisterError:
                    raise
                except Exception as exc:
                    transitioned_state = self._classify_page(driver)
                    if transitioned_state in {"otp", "login_password", "signup_password", "home", "security", "profile", "oauth_callback"}:
                        email_already_submitted = True
                        auth_state = transitioned_state
                        log(f"等待邮箱输入框期间认证页已继续：{transitioned_state}", "info")
                        if transitioned_state == "otp":
                            otp.mark_sent()
                    else:
                        try:
                            body = str(driver.find_element("tag name", "body").text or "").lower()
                        except Exception:
                            body = ""
                        challenge = any(token in body for token in ("cloudflare", "verify you are human", "安全验证", "turnstile", "just a moment"))
                        node_code = "free_roxy_challenge" if challenge else "free_roxy_signup_email"
                        node_label = "等待注册页安全验证" if challenge else "填写 Free 注册邮箱"
                        message = "注册页出现安全验证，邮箱输入框未开放" if challenge else f"45 秒内未找到可用邮箱输入框（{self._safe_page_location(driver)}）"
                        raise FreeRegisterError(node_code, node_label, message, error_code=f"{node_code}_timeout") from exc
            if auth_state == "login_password":
                if not bool(roxy.get("existing_account_login", True)):
                    raise FreeRegisterError(
                        "free_roxy_login_password", "识别登录密码页",
                        f"邮箱已存在账号，且未开启邮箱验证码登录兜底（{safe_page_location(driver)}）",
                        retryable=False,
                        error_code="free_existing_login_disabled",
                    )
                account_flow = "existing_login"
                set_stage("free_existing_login")
                operation_started = time.monotonic()
                set_stage("free_existing_login_otp")
                self._switch_login_to_email_code(driver, human, log)
                auth_state = self._wait_after_passwordless_switch(driver, 45, log)
                if auth_state == "otp":
                    otp.mark_sent("free_existing_login_otp")
                log(
                    f"已有账号登录已切换到邮箱验证码，下一页={auth_state}，"
                    f"duration_ms={int((time.monotonic() - operation_started) * 1000)} outcome=success",
                    "success",
                )
            if auth_state == "signup_password":
                if account_flow == "existing_login":
                    raise FreeRegisterError(
                        "free_existing_login", "已有 Free 账号登录",
                        f"切换邮箱验证码后意外进入注册密码页（{safe_page_location(driver)}）",
                        retryable=False,
                        error_code="free_existing_login_wrong_page",
                    )
                set_stage("free_roxy_signup_password")
                try:
                    auth_state = self._submit_signup_password(driver, human, log)
                    registration_password_used = True
                    if auth_state == "otp":
                        otp.mark_sent()
                except FreeRegisterError:
                    raise
                except Exception as exc:
                    raise FreeRegisterError(
                        "free_roxy_signup_password", "提交 Free 注册密码",
                        f"注册密码提交失败（{type(exc).__name__}，{self._safe_page_location(driver)}）",
                        error_code="free_roxy_signup_password_timeout" if "timeout" in type(exc).__name__.casefold() else "free_roxy_signup_password_submit_failed",
                    ) from exc
            if auth_state == "security":
                raise FreeRegisterError(
                    "free_roxy_challenge", "等待注册页安全验证",
                    f"邮箱认证后进入安全验证页（{safe_page_location(driver)}）",
                    retryable=False,
                    error_code="free_roxy_security_challenge",
                )
            post_otp_state = auth_state
            if auth_state == "otp":
                otp_stage = "free_existing_login_otp" if account_flow == "existing_login" else "free_email_otp_wait"
                def wait_code(otp_attempt: int) -> str:
                    set_stage(otp_stage)
                    operation_started = time.monotonic()
                    log(
                        f"开始等待本账号的{'已有账号登录' if account_flow == 'existing_login' else '注册'}邮箱验证码"
                        f"（第 {otp_attempt}/3 次）",
                        "info",
                    )
                    code = self._wait_mailbox_code(
                        otp, str(task.get("email") or ""), otp_stage, driver, human, log,
                    )
                    log(
                        "邮箱验证码已收到，未记录验证码内容"
                        f"，duration_ms={int((time.monotonic() - operation_started) * 1000)} outcome=success",
                        "success",
                    )
                    return str(code or "").strip()

                def submit_code(code: str, _otp_attempt: int) -> str:
                    set_stage("free_existing_login_otp" if account_flow == "existing_login" else "free_email_otp_validate")
                    fill_result = self._fill_otp(driver, code, human) or {}
                    if not isinstance(fill_result, Mapping):
                        fill_result = {}
                    log(
                        "邮箱验证码已输入并提交，等待离开验证码页"
                        f"（输入框={fill_result.get('input_count') or '-'}，"
                        f"提交动作={'已触发' if fill_result.get('submit_clicked') else '未确认'}，"
                        f"位置={safe_page_location(driver)}）",
                        "info",
                    )
                    human.delay("navigate")
                    post_otp_state = self._wait_after_otp_submit(driver, 45, log)
                    continue_url = wait_for_continue_url(driver, 2.0)
                    if continue_url and post_otp_state in {"oauth_callback", "home", "profile"}:
                        post_otp_state = follow_oauth_continue(driver, continue_url, 45, log)
                    return post_otp_state

                def restart_flow(_next_attempt: int) -> str:
                    return reopen_email_otp_flow(
                        driver,
                        str(task.get("email") or ""),
                        account_flow,
                        otp,
                        otp_stage,
                        human,
                        log,
                        int(roxy.get("selenium_timeout") or 90),
                        open_signup_page=self._open_signup_page,
                        classify=self._classify_page,
                        find_element=self._find,
                        type_element=self._type,
                        submit=self._submit,
                        wait_after_email_submit=self._wait_after_email_submit,
                        switch_login_to_email_code=self._switch_login_to_email_code,
                        wait_after_passwordless_switch=self._wait_after_passwordless_switch,
                        submit_signup_password=self._submit_signup_password,
                        submit_email=self._submit_registration_email,
                    )

                def reload_flow(_attempt: int) -> str:
                    return reload_otp_page(driver, 30, log)

                post_otp_state = run_otp_attempts(
                    wait_code=wait_code,
                    submit_code=submit_code,
                    restart_flow=restart_flow,
                    reload_flow=reload_flow,
                    log=log,
                    max_attempts=3,
                )
            if post_otp_state == "login_password":
                node_code = "free_existing_login" if account_flow == "existing_login" else "free_roxy_login_password"
                node_label = "已有 Free 账号登录" if account_flow == "existing_login" else "识别登录密码页"
                raise FreeRegisterError(
                    node_code, node_label,
                    f"邮箱验证码后仍进入登录密码页（{safe_page_location(driver)}）",
                    retryable=False,
                    error_code="free_existing_login_password_returned" if account_flow == "existing_login" else "free_roxy_login_password_page",
                )
            if post_otp_state == "security":
                raise FreeRegisterError("free_roxy_challenge", "等待注册页安全验证", f"OTP 后进入安全验证页（{safe_page_location(driver)}）", retryable=False, error_code="free_roxy_security_challenge")
            if post_otp_state == "signup_password":
                if account_flow == "existing_login":
                    raise FreeRegisterError(
                        "free_existing_login", "已有 Free 账号登录",
                        f"已有账号邮箱验证码后进入注册密码页（{safe_page_location(driver)}）",
                        retryable=False,
                        error_code="free_existing_login_wrong_page",
                    )
                set_stage("free_roxy_signup_password")
                post_otp_state = self._submit_signup_password(driver, human, log)
                registration_password_used = True
            if post_otp_state == "profile":
                set_stage("free_roxy_profile")
                self._complete_profile(driver, human, log)
                human.delay("post_auth")
                self._wait_for_home(driver, 60, log)
            elif post_otp_state == "oauth_callback":
                self._wait_for_home(driver, 60, log)
            elif post_otp_state != "home":
                raise FreeRegisterError("free_roxy_page_state", "确认 ChatGPT 登录首页", f"OTP 后页面状态未确认（{post_otp_state}，{safe_page_location(driver)}）", error_code="free_roxy_home_not_confirmed")
            log(f"账号流程确认：{'已有账号邮箱验证码登录' if account_flow == 'existing_login' else '新账号注册'}，ChatGPT 首页已建立登录态", "success")
            set_stage("free_access_token")
            session = self._session(driver, 120, log)
            token = session_token(session)
            if not token:
                raise FreeRegisterError("free_access_token", "获取 Free access token", "Session 已返回但未发现兼容 Token 字段", error_code="free_session_token_missing")
            log("已确认 ChatGPT 首页登录态，开始读取 Session Token", "info")
            set_stage("free_plan_check")
            operation_started = time.monotonic()
            try:
                plan_details = self._plan_details(driver, token)
                if plan_details.get("plan_failure"):
                    log(f"套餐信息部分读取成功：套餐={plan_details.get('plan_type') or '-'}，Plus 资格读取失败，duration_ms={int((time.monotonic() - operation_started) * 1000)} outcome=warning", "warn")
                else:
                    log(f"套餐查询完成：套餐={plan_details.get('plan_type') or '-'}，Plus 试用={'可用' if plan_details.get('plus_trial_eligible') else '不可用'}，duration_ms={int((time.monotonic() - operation_started) * 1000)} outcome=success", "success")
            except FreeRegisterError as exc:
                log(f"套餐查询失败但保留注册结果：{safe_log_message(exc)}，duration_ms={int((time.monotonic() - operation_started) * 1000)} outcome=warning", "warn")
                plan_failure = _structured_failure(
                    exc,
                    action_hint="保留已注册账号，稍后重新查询套餐状态",
                )
                partial = getattr(exc, "partial_plan_details", None)
                plan_details = {
                    "plan_check_status": "failed",
                    "plan_checked_at": time.time(),
                    "plan_error_code": plan_failure["error_code"],
                    "plan_http_status": plan_failure.get("http_status"),
                    "plan_type": "",
                    "subscription_plan": "",
                    "has_active_subscription": False,
                    "plus_trial_eligible": False,
                    **(dict(partial) if isinstance(partial, Mapping) else {}),
                    "plan_failure": plan_failure,
                }
            twofa_status = "disabled"
            totp_secret = ""
            twofa_error = ""
            twofa_failure: dict[str, Any] | None = None
            if bool(config.get("auto_set_2fa", True)):
                def capture_twofa_token(value: str) -> None:
                    nonlocal token
                    if value:
                        token = value

                try:
                    totp_secret = self._setup_2fa(
                        driver, task, token, otp, human, set_stage, capture_twofa_token,
                    )
                    twofa_status = "enabled"
                    log("2FA enrollment/activation 完成，密钥仅保存到受保护结果中", "success")
                except FreeRegisterError as exc:
                    twofa_status = "pending"
                    twofa_error = safe_log_message(exc)
                    twofa_failure = _structured_failure(
                        exc,
                        action_hint="保留已注册账号和 Token，稍后重试 2FA",
                    )
                except Exception as exc:
                    twofa_status = "pending"
                    twofa_error = f"2FA 设置失败（{type(exc).__name__}）"
                    failure = FreeRegisterError(
                        "free_twofa_activate", "激活 Free 账号 2FA",
                        twofa_error,
                        error_code="free_twofa_activate_failed",
                        provider_code=type(exc).__name__,
                        action_hint="保留已注册账号和 Token，检查日志后重试 2FA",
                    )
                    twofa_failure = _structured_failure(
                        failure,
                        action_hint="保留已注册账号和 Token，检查日志后重试 2FA",
                    )
            dwell_min = int(roxy.get("post_registration_dwell_min") or 18)
            dwell_max = max(dwell_min, int(roxy.get("post_registration_dwell_max") or 45))
            if dwell_max > 0:
                time.sleep(random.uniform(dwell_min, dwell_max))
            result = {
                "driver": "roxybrowser", "access_token": token, "account_flow": account_flow,
                **plan_details, "twofa_status": twofa_status,
                "twofa_error": twofa_error, "registration_ip": registration_ip,
                "expected_exit_ip": "", "profile_summary": f"Roxy#{profile_id}",
                "registration_password_used": registration_password_used,
            }
            if twofa_failure:
                result["twofa_failure"] = twofa_failure
            if totp_secret:
                result["totp_secret"] = totp_secret
            return finalize_registration_result(
                result,
                driver="roxybrowser",
                email=str(task.get("email") or ""),
                password_used=registration_password_used,
            )
        except FreeRegisterError as exc:
            if driver is not None:
                if not getattr(exc, "safe_page", ""):
                    exc.safe_page = safe_page_location(driver)
                if not getattr(exc, "page_type", ""):
                    try:
                        exc.page_type = str(classify_page(driver) or "")[:120]
                    except Exception:
                        pass
            raise
        except Exception as exc:
            error_type = type(exc).__name__
            lowered = error_type.casefold()
            if isinstance(exc, FreeRegisterError):
                raise
            if "ssl" in lowered:
                node_code, node_label, error_code = active_stage, "RoxyBrowser 当前页面网络请求", f"{active_stage}_ssl_error"
            elif "timeout" in lowered:
                node_code, node_label, error_code = active_stage, "RoxyBrowser 当前页面等待", f"{active_stage}_timeout"
            elif "proxy" in lowered or "connection" in lowered:
                node_code, node_label, error_code = active_stage, "RoxyBrowser 当前页面连接", f"{active_stage}_connection_error"
            else:
                node_code, node_label, error_code = active_stage, "RoxyBrowser 当前操作", f"{active_stage}_failed"
            detail = f"{node_label}失败（{error_type}，页面 {safe_page_location(driver) if driver is not None else '页面地址未知'}）"
            log(f"{detail}，请根据当前节点重试", "error")
            page_type = ""
            if driver is not None:
                try:
                    page_type = str(classify_page(driver) or "")[:120]
                except Exception:
                    pass
            raise FreeRegisterError(
                node_code, node_label, detail, error_code=error_code,
                page_type=page_type,
                safe_page=safe_page_location(driver) if driver is not None else "页面地址未知",
            ) from exc
        finally:
            cleanup_started = time.monotonic()
            cleanup_ok = True
            otp_close = getattr(otp, "close", None)
            if callable(otp_close):
                try:
                    otp_close()
                except Exception as exc:
                    cleanup_ok = False
                    log(f"[清理 RoxyBrowser 环境/free_roxy_cleanup] 邮箱取件关闭失败（{type(exc).__name__}）", "warn")
            if driver is not None and not bool(roxy.get("keep_browser_open", False)):
                try:
                    driver.quit()
                except Exception as exc:
                    cleanup_ok = False
                    log(f"[清理 RoxyBrowser 环境/free_roxy_cleanup] Selenium 关闭失败（{type(exc).__name__}）", "warn")
            # Cleanup is diagnostic only; do not overwrite the terminal stage
            # (for example free_roxy_connect) with a cleanup stage.
            log(f"[{task_id}/清理 RoxyBrowser 环境/free_roxy_cleanup] 开始", "info")
            try:
                cleanup_ok = client.cleanup(opened) is not False and cleanup_ok
            except Exception as exc:
                cleanup_ok = False
                log(f"[{task_id}/清理 RoxyBrowser 环境/free_roxy_cleanup] 清理异常（{type(exc).__name__}）", "warn")
            duration_ms = int((time.monotonic() - cleanup_started) * 1000)
            if opened is None or not opened.profile_id:
                log(f"[{task_id}/清理 RoxyBrowser 环境/free_roxy_cleanup] 未创建 Profile，无需清理，duration_ms={duration_ms} outcome=success", "info")
            elif cleanup_ok:
                log(f"[{task_id}/清理 RoxyBrowser 环境/free_roxy_cleanup] 清理完成并确认释放，duration_ms={duration_ms} outcome=success", "success")
            else:
                log(f"[{task_id}/清理 RoxyBrowser 环境/free_roxy_cleanup] 清理未完全完成，原始注册结果已保留，duration_ms={duration_ms} outcome=warning", "warn")


__all__ = ["RoxyBrowserClient", "RoxyOpenResult", "RoxyRegistrationRunner", "proxy_to_roxy_info"]
