"""Re-authentication and TOTP enrollment for the Free Roxy flow."""

from __future__ import annotations

from typing import Any, Callable, Mapping

try:
    from .free_register_common import FreeRegisterError
    from .free_roxy_otp_flow import follow_oauth_continue, wait_for_continue_url
    from .free_roxy_signup import safe_page_location
except ImportError:
    from free_register_common import FreeRegisterError  # type: ignore[no-redef]
    from free_roxy_otp_flow import follow_oauth_continue, wait_for_continue_url  # type: ignore[no-redef]
    from free_roxy_signup import safe_page_location  # type: ignore[no-redef]


StageFn = Callable[[str, str], None]
SessionFn = Callable[[Any, int], dict[str, Any]]
FillOtpFn = Callable[[Any, str, Any], Mapping[str, Any]]
WaitFn = Callable[..., str]
HomeFn = Callable[..., None]


def setup_twofa(
    driver: Any,
    task: Mapping[str, Any],
    token: str,
    otp: Any,
    human: Any,
    stage: StageFn,
    *,
    session_fn: SessionFn,
    fill_otp_fn: FillOtpFn,
    wait_after_otp_fn: WaitFn,
    wait_home_fn: HomeFn,
    totp_fn: Callable[[str], str],
) -> str:
    """Run re-auth OTP, OAuth callback, enrollment and activation once."""
    task_id = str(task.get("task_id") or "")
    email = str(task.get("email") or "")
    stage(task_id, "free_twofa_enroll")
    prepare = getattr(otp, "prepare", None)
    if callable(prepare):
        try:
            prepare("free_twofa_enroll", force_snapshot=True)
        except TypeError as exc:
            if "force_snapshot" not in str(exc):
                raise
            try:
                prepare("free_twofa_enroll")
            except TypeError as legacy_exc:
                if "argument" not in str(legacy_exc) and "positional" not in str(legacy_exc):
                    raise
                prepare()
    signin = driver.execute_async_script(
        """
        const email=arguments[0], done=arguments[arguments.length - 1];
        fetch('/api/auth/csrf',{credentials:'include'}).then(r=>r.json()).then(csrf=>{
          const q=new URLSearchParams({connection:'password',login_hint:email,reauth:'password',max_age:'0'});
          const body=new URLSearchParams({callbackUrl:'https://chatgpt.com/?action=enable&factor=totp',csrfToken:csrf.csrfToken,json:'true'});
          return fetch('/api/auth/signin/openai?'+q,{method:'POST',credentials:'include',headers:{'content-type':'application/x-www-form-urlencoded'},body});
        }).then(r=>r.json()).then(v=>done({ok:true,url:v.url})).catch(e=>done({ok:false,error:String(e)}));
        """,
        email,
    ) or {}
    if not signin.get("ok") or not signin.get("url"):
        raise FreeRegisterError("free_twofa_enroll", "注册 Free 账号 2FA", "RoxyBrowser 未能发起 2FA 重认证")
    driver.get(str(signin["url"]))
    mark_sent = getattr(otp, "mark_sent", None)
    if callable(mark_sent):
        try:
            mark_sent("free_twofa_enroll")
        except TypeError as exc:
            if "argument" not in str(exc) and "positional" not in str(exc):
                raise
            mark_sent()
    try:
        code = otp.wait_code(email, stage_code="free_twofa_enroll")
    except TypeError as exc:
        if "unexpected keyword" not in str(exc):
            raise
        try:
            code = otp.wait_code(email, "free_twofa_enroll")
        except TypeError as legacy_exc:
            if "argument" not in str(legacy_exc) and "positional" not in str(legacy_exc):
                raise
            code = otp.wait_code(email)
    fill_otp_fn(driver, code, human)
    state = wait_after_otp_fn(driver, 45)
    continue_url = wait_for_continue_url(driver, 2.0)
    if continue_url:
        state = follow_oauth_continue(driver, continue_url, 45)
    if state == "security":
        raise FreeRegisterError(
            "free_twofa_enroll", "注册 Free 账号 2FA",
            f"2FA 邮箱验证后进入安全验证页（{safe_page_location(driver)}）",
            retryable=False,
            error_code="free_roxy_security_challenge",
        )
    if state not in {"home", "oauth_callback"}:
        raise FreeRegisterError(
            "free_twofa_enroll", "注册 Free 账号 2FA",
            f"2FA 邮箱验证后未回到 ChatGPT 首页（{state}，{safe_page_location(driver)}）",
            error_code="free_twofa_callback_not_confirmed",
        )
    wait_home_fn(driver, 60)
    refreshed = session_fn(driver, 90)
    new_token = str(refreshed.get("accessToken") or token)
    enrolled = driver.execute_async_script(
        """
        const token=arguments[0], done=arguments[arguments.length - 1]; fetch('https://chatgpt.com/backend-api/accounts/mfa/enroll',{
          method:'POST',credentials:'include',headers:{authorization:'Bearer '+token,'content-type':'application/json'},body:JSON.stringify({factor_type:'totp'})
        }).then(async r=>done({ok:r.ok,status:r.status,value:await r.json().catch(()=>({}))})).catch(e=>done({ok:false,error:String(e)}));
        """,
        new_token,
    ) or {}
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
    activated = driver.execute_async_script(
        """
        const token=arguments[0], code=arguments[1], sid=arguments[2], done=arguments[arguments.length - 1]; fetch('https://chatgpt.com/backend-api/accounts/mfa/user/activate_enrollment',{
          method:'POST',credentials:'include',headers:{authorization:'Bearer '+token,'content-type':'application/json'},body:JSON.stringify({code,factor_type:'totp',session_id:sid})
        }).then(async r=>done({ok:r.ok,status:r.status,value:await r.json().catch(()=>({}))})).catch(e=>done({ok:false,error:String(e)}));
        """,
        new_token,
        totp_fn(secret),
        session_id,
    ) or {}
    value = activated.get("value") if isinstance(activated.get("value"), Mapping) else {}
    if not activated.get("ok") or not value.get("success"):
        status = activated.get("status") or None
        raise FreeRegisterError(
            "free_twofa_activate", "激活 Free 账号 2FA",
            f"RoxyBrowser 2FA 激活失败（HTTP {status or '-'}）",
            provider_status=status,
        )
    return secret


__all__ = ["setup_twofa"]
