"""The bounded Camoufox browser registration flow.

Split out of ``free_camoufox_runtime``; every callable receives the hosting
runtime module as its first ``host`` argument so tests and integrations can
keep patching ``free_camoufox_runtime.<name>`` globals with unchanged
semantics.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import time
from typing import Any, Callable, Mapping

try:
    from .selectors import (
        AGE_SELECTORS,
        BIRTHDAY_SELECTORS,
        CHATGPT_LOGIN_URL,
        EMAIL_SELECTORS,
        EMAIL_SUBMIT_SELECTORS,
        NAME_SELECTORS,
        OTP_SELECTORS,
        PASSWORD_SELECTORS,
        PASSWORD_SUBMIT_SELECTORS,
        PROFILE_SUBMIT_SELECTORS,
        RESEND_SELECTORS,
    )
except ImportError:  # pragma: no cover - top-level recovery import
    from free_camoufox.selectors import (  # type: ignore[no-redef]
        AGE_SELECTORS,
        BIRTHDAY_SELECTORS,
        CHATGPT_LOGIN_URL,
        EMAIL_SELECTORS,
        EMAIL_SUBMIT_SELECTORS,
        NAME_SELECTORS,
        OTP_SELECTORS,
        PASSWORD_SELECTORS,
        PASSWORD_SUBMIT_SELECTORS,
        PROFILE_SUBMIT_SELECTORS,
        RESEND_SELECTORS,
    )
try:
    from .deadline import (
        MANUAL_OTP_POST_SUBMIT_GRACE_SECONDS,
        ProfileTimingTracker,
        RegistrationBudget,
        RegistrationDeadline,
    )
except ImportError:  # pragma: no cover - top-level recovery import
    from free_camoufox.deadline import (  # type: ignore[no-redef]
        MANUAL_OTP_POST_SUBMIT_GRACE_SECONDS,
        ProfileTimingTracker,
        RegistrationBudget,
        RegistrationDeadline,
    )

# Poll cadence for the page-state machine. Tighter than the historic 1s waits
# so a finished navigation is observed roughly half a wait earlier; the stuck
# counters and step limits below are scaled to keep wall-clock semantics.
_STATE_POLL_SECONDS = 0.5
# Submit-transition polling shares the state cadence; the 12s/45s/60s submit
# windows below are wall-clock comparisons, so the tighter cadence only
# observes the same transitions sooner.
_SUBMIT_POLL_SECONDS = _STATE_POLL_SECONDS
# seen[state] guard fires after >4 consecutive polls at the historic 1s cadence
# (~5s); with a 0.5s cadence the same wall-clock budget needs >8 polls.
_STATE_STUCK_POLLS = 8





async def _finish_home_flow(
    host,
    page: Any,
    *,
    email: str,
    password: str,
    config: Mapping[str, Any],
    controller: Any,
    deadline_fn: Callable[[], float],
    account_flow: str,
    login_password_submitted: bool,
    password_used: bool,
    otp_callback: Callable[[], str],
    otp_prepare: Callable[..., Any] | None,
    otp_mark_sent: Callable[..., Any] | None,
    timing_fn: Callable[..., Any] | None,
    set_stage: Callable[[str], None],
) -> dict[str, Any]:
    """Finalize a landed home session into the persisted registration result."""
    if callable(timing_fn):
        session = await host.browser_session(
            page,
            timing_fn=timing_fn,
            timing_stage="free_access_token",
        )
    else:
        session = await host.browser_session(page)
    set_stage("free_access_token")
    token = str(session.get("accessToken") or "")
    if callable(timing_fn):
        plan = await host.browser_plan_details(
            page,
            token,
            timing_fn=timing_fn,
            timing_stage="free_access_token",
        )
    else:
        plan = await host.browser_plan_details(page, token)
    set_stage("free_plan_check")
    result: dict[str, Any] = {
        "access_token": token,
        "has_access_token": bool(token),
        "account_flow": account_flow,
        "registration_password_used": password_used,
        **plan,
    }
    password_set_after_registration = False
    if account_flow == "signup" and password_used:
        result.update({
            "password_status": "enabled",
            "password_set_after_registration": False,
            "password": password,
        })
    elif account_flow == "existing_login" and login_password_submitted:
        # Authentication just succeeded with the saved credential, so the
        # password exists even though this session never created it.
        result.update({
            "password_status": "enabled",
            "password_set_after_registration": False,
        })
    elif host._runtime_bool(config.get("auto_set_password"), False):
        try:
            password_result = await host.browser_add_password(
                page,
                token,
                email,
                password,
                otp_callback=otp_callback,
                otp_prepare=otp_prepare,
                otp_mark_sent=otp_mark_sent,
                stage_fn=set_stage,
                task_id=str(config.get("task_id") or ""),
                device_id=str(config.get("device_id") or ""),
                deadline_monotonic=deadline_fn(),
                deadline_controller=controller,
                stop_requested=config.get("host._stop_requested"),
                timing_fn=timing_fn,
            )
            result.update(password_result)
            token = str(password_result.get("access_token") or token)
            password_set_after_registration = bool(
                password_result.get("password_set_after_registration")
            )
        except host.FreeRegisterError as exc:
            if exc.error_code == "free_run_stop" or exc.node_code == "free_run_stop":
                raise
            detail = host.clean(str(exc), 300)
            result.update({
                "password_status": "pending",
                "password_error": detail,
                "password_failure": {
                    "node_code": exc.node_code,
                    "node_label": exc.node_label,
                    "error_code": exc.error_code,
                    "public_message": f"{exc.node_label} [{exc.node_label}/{exc.node_code}]：{detail}",
                    "technical_summary": detail,
                    "retryable": bool(exc.retryable),
                    "provider_code": str(exc.provider_code or ""),
                },
            })
    else:
        result["password_status"] = "disabled"

    # Keep the two security operations independent. Each helper owns its
    # own mailbox baseline and therefore consumes a distinct OTP.
    if host._runtime_bool(config.get("auto_set_2fa"), True):
        set_stage("free_twofa_enroll")
        try:
            twofa_result = await host.browser_twofa(
                page,
                token,
                email,
                otp_callback=otp_callback,
                otp_prepare=otp_prepare,
                otp_mark_sent=otp_mark_sent,
                stage_fn=lambda code: set_stage(code),
                task_id=str(config.get("task_id") or ""),
                device_id=str(config.get("device_id") or ""),
                deadline_monotonic=deadline_fn(),
                deadline_controller=controller,
                stop_requested=config.get("host._stop_requested"),
                timing_fn=timing_fn,
            )
            if isinstance(twofa_result, Mapping):
                result.update(twofa_result)
                token = str(twofa_result.get("access_token") or token)
            else:  # pragma: no cover - compatibility with old adapters
                result.update({"totp_secret": str(twofa_result or "")})
            set_stage("free_twofa_activate")
            result["twofa_status"] = "enabled"
        except host.FreeRegisterError as exc:
            if exc.error_code == "free_run_stop" or exc.node_code == "free_run_stop":
                raise
            result.update({
                "twofa_status": "pending",
                "twofa_error": host.clean(str(exc), 300),
                "twofa_failure": {
                    "node_code": exc.node_code, "node_label": exc.node_label,
                    "error_code": exc.error_code,
                    "public_message": f"{exc.node_label} [{exc.node_label}/{exc.node_code}]：{host.clean(str(exc), 300)}",
                    "retryable": bool(exc.retryable), "provider_code": exc.provider_code,
                },
            })
    else:
        result["twofa_status"] = "disabled"
    result["access_token"] = token
    result["has_access_token"] = bool(token)
    result["password_set_after_registration"] = bool(
        result.get("password_set_after_registration") or password_set_after_registration
    )
    return host.finalize_registration_result(
        result,
        driver="camoufox",
        email=email,
        password_used=password_used or bool(result.get("password_set_after_registration")),
    )


async def _finish_password_retry_flow(
    host,
    page: Any,
    *,
    email: str,
    password: str,
    config: Mapping[str, Any],
    controller: Any,
    deadline_fn: Callable[[], float],
    password_retry_token: str,
    otp_callback: Callable[[], str],
    otp_prepare: Callable[..., Any] | None,
    otp_mark_sent: Callable[..., Any] | None,
    timing_fn: Callable[..., Any] | None,
    set_stage: Callable[[str], None],
) -> dict[str, Any]:
    """Run only the post-registration password continuation.

    A password retry has an account Token already. It must not open the
    signup entry, submit the mailbox address, or invoke the 2FA helper.
    ``browser_add_password`` owns the independent OTP baseline and the
    Auth/ChatGPT callback sequence.
    """
    token = str(password_retry_token or "").strip()
    if not token:
        raise host.CamoufoxBrowserError(
            "free_password_retry", "重试 Free 账号密码设置",
            "原账号没有可用 access token", retryable=False,
            error_code="free_password_retry_token_missing",
        )
    # ``browser_json_fetch`` is evaluated in the page's origin. Start from
    # ChatGPT home when a concrete Playwright page is available, but keep
    # compatibility with lightweight test doubles that only implement
    # ``evaluate``.
    goto = getattr(page, "goto", None)
    if callable(goto):
        try:
            try:
                await goto("https://chatgpt.com/", wait_until="domcontentloaded", timeout=45_000)
            except TypeError:
                await goto("https://chatgpt.com/", timeout=45_000)
        except Exception as exc:
            raise host.CamoufoxBrowserError(
                "free_password_reauth_authorize", "打开密码设置授权页面",
                f"密码设置前 ChatGPT 页面跳转失败（{type(exc).__name__}）",
                retryable=True, error_code="free_password_retry_navigation_failed",
                safe_page=host._safe_url(page), page_type="password_retry",
            ) from exc
    set_stage("free_password_eligibility")
    try:
        result = await host.browser_add_password(
            page,
            token,
            email,
            password,
            otp_callback=otp_callback,
            otp_prepare=otp_prepare,
            otp_mark_sent=otp_mark_sent,
            stage_fn=set_stage,
            task_id=str(config.get("task_id") or ""),
            device_id=str(config.get("device_id") or ""),
            deadline_monotonic=deadline_fn(),
            deadline_controller=controller,
            stop_requested=config.get("host._stop_requested"),
            timing_fn=timing_fn,
        )
    except host.FreeRegisterError as exc:
        if exc.error_code == "free_run_stop" or exc.node_code == "free_run_stop":
            raise
        detail = host.clean(str(exc), 300)
        return {
            "access_token": token,
            "has_access_token": True,
            "account_flow": "signup",
            "registration_password_used": False,
            "password_set_after_registration": False,
            "password_status": "pending",
            "password_error": detail,
            "password_failure": {
                "node_code": exc.node_code,
                "node_label": exc.node_label,
                "error_code": exc.error_code,
                "public_message": f"{exc.node_label} [{exc.node_label}/{exc.node_code}]：{detail}",
                "technical_summary": detail,
                "retryable": bool(exc.retryable),
                "provider_code": str(exc.provider_code or ""),
            },
        }
    output = dict(result) if isinstance(result, Mapping) else {}
    output.setdefault("access_token", token)
    output["has_access_token"] = bool(output.get("access_token"))
    output.setdefault("account_flow", "signup")
    output.setdefault("registration_password_used", False)
    output["password_set_after_registration"] = bool(
        output.get("password_set_after_registration")
    )
    return host.finalize_registration_result(
        output,
        driver="camoufox",
        email=email,
        password_used=bool(output.get("password_set_after_registration")),
    )


async def _browser_flow(
    host,
    page: Any,
    *,
    email: str,
    password: str,
    proxy: str = "",
    otp_callback: Callable[[], str],
    config: Mapping[str, Any],
    log: Callable[[str, str], None],
    otp_prepare: Callable[..., Any] | None = None,
    otp_mark_sent: Callable[..., Any] | None = None,
    stage_fn: Callable[[str, str], None] | None = None,
    timing_fn: host.TimingCallback | None = None,
    force_existing_login: bool = False,
    existing_password: str = "",
    password_retry: bool = False,
    password_retry_token: str = "",
    startup_gate: asyncio.Semaphore | None = None,
    deadline_controller: RegistrationDeadline | None = None,
) -> dict[str, Any]:
    timeout = max(60, int(config.get("registration_timeout_seconds") or 600))
    controller = deadline_controller or config.get("_deadline_controller")
    if controller is None:
        controller = RegistrationDeadline(timeout)
    fallback_deadline = time.monotonic() + timeout
    budget = RegistrationBudget(host, controller, fallback_deadline=fallback_deadline)

    def current_deadline() -> float:
        return budget.deadline()

    def budget_remaining() -> float:
        return budget.remaining()

    def budget_paused() -> bool:
        return budget.paused()

    def budget_grace_active() -> bool:
        return budget.grace_active()

    def budget_grace_remaining() -> float:
        return budget.grace_remaining()

    def budget_expired() -> bool:
        return budget.expired()

    deadline = current_deadline()
    account_flow = "existing_login" if force_existing_login else "signup"
    # The manager passes the configured value for normal runs, but resolving
    # it here also keeps direct browser-flow callers aligned with Free config.
    password = str(password or host.configured_free_password(config))
    password_used = False
    entry_submitted = False
    otp_submitted = False
    otp_submitted_at = 0.0
    # Keep the stage that actually supplied the submitted code.  The entry
    # stage can be ``free_email_otp_wait`` even when the flow later discovers
    # that the address belongs to an existing account.
    otp_submitted_stage = ""
    otp_transition_recorded = False
    otp_resend_used = False
    otp_input_selector = ""
    password_stage_started_at = 0.0
    password_submitted_at = 0.0
    password_submit_retried = False
    login_password_submitted = False
    login_password_submitted_at = 0.0
    login_password_submit_retried = False
    passwordless_login_switch_used = False
    email_verification_started_at = 0.0
    email_verification_retried = False
    profile_submitted = False
    profile_submitted_at = 0.0
    # ``profile_submitted_at`` guards the reference flow's 60s retry window;
    # the timing anchors below describe two non-overlapping intervals:
    # request completion (leaving profile) and subsequent home confirmation.
    profile_async_started_at = 0.0
    profile_timing = ProfileTimingTracker()
    entry_transition_deadline = 0.0
    entry_transition_observe_deadline = 0.0
    entry_transition_started = 0.0
    entry_transition_recorded = False
    entry_retry_used = False
    entry_signin_fallback_used = False
    entry_reload_recovery_used = False
    entry_recovery = "none"
    entry_form_present = False
    entry_submit_selector = ""
    mailbox_lease_confirmed = False
    mailbox_confirmation_abortable = False
    mailbox_lease_callback = config.get("_confirm_mailbox_lease")
    mailbox_abort_callback = config.get("_abort_mailbox_lease_confirmation")
    # Once an OTP/password/profile/auth page is observed, returning to the
    # email entry shell is a terminal navigation inconsistency. Re-submitting
    # the address could consume another OTP or duplicate account creation.
    auth_phase_locked = False
    seen: dict[str, int] = {}
    step_count = 0
    entry_otp_stage = "free_existing_login_otp" if force_existing_login else "free_email_otp_wait"

    # A missing saved credential no longer aborts a 2FA retry: passwordless
    # accounts continue through the mailbox verification-code login below.

    def timing_mark(stage_code: str, code: str, started: float, outcome: str = "success") -> None:
        host.emit_timing(
            timing_fn,
            stage_code,
            code,
            max(0.0, (time.monotonic() - started) * 1000.0),
            outcome,
        )

    def set_stage(code: str) -> None:
        if callable(stage_fn):
            stage_fn(str(config.get("task_id") or ""), code)

    async def confirm_mailbox_before_submit() -> None:
        """Confirm the mailbox only after a visible entry form is prepared."""
        nonlocal mailbox_lease_confirmed, mailbox_confirmation_abortable
        if mailbox_lease_confirmed or not callable(mailbox_lease_callback):
            return
        try:
            outcome = await asyncio.to_thread(
                host._invoke_mailbox_lease_callback,
                mailbox_lease_callback,
                task_id=str(config.get("task_id") or ""),
                email=email,
                driver="camoufox",
                stage="free_camoufox_signup_email",
            )
        except host.FreeRegisterError:
            raise
        except Exception as exc:
            raise host.CamoufoxBrowserError(
                "free_mailbox_lease",
                "确认 Free 邮箱租约",
                "提交邮箱前确认租约失败",
                retryable=True,
                error_code="free_mailbox_lease_confirm_failed",
                diagnostic=f"callback={type(exc).__name__}",
                safe_page=host._safe_url(page),
                page_type="entry",
            ) from exc
        if outcome is False:
            raise host.CamoufoxBrowserError(
                "free_mailbox_lease",
                "确认 Free 邮箱租约",
                "提交邮箱前邮箱租约已失效或被其他任务占用",
                retryable=True,
                error_code="free_mailbox_lease_conflict",
                safe_page=host._safe_url(page),
                page_type="entry",
            )
        mailbox_lease_confirmed = True
        mailbox_confirmation_abortable = True

    async def abort_mailbox_confirmation_before_submit() -> bool:
        """Undo only the confirmation for a submit that provably never ran."""
        nonlocal mailbox_lease_confirmed, mailbox_confirmation_abortable
        if (
            not mailbox_lease_confirmed
            or not mailbox_confirmation_abortable
            or not callable(mailbox_abort_callback)
        ):
            return False
        # The authorization is one-shot. An exception or failed CAS leaves
        # the durable confirmation intact and therefore conservatively keeps
        # the mailbox pending for an explicit rerun.
        mailbox_confirmation_abortable = False
        try:
            outcome = await asyncio.to_thread(
                host._invoke_mailbox_lease_callback,
                mailbox_abort_callback,
                task_id=str(config.get("task_id") or ""),
                email=email,
                driver="camoufox",
                stage="free_camoufox_signup_email",
                submission_definitely_not_started=True,
            )
        except Exception as exc:
            log(
                f"Camoufox 邮箱租约确认撤销失败（{type(exc).__name__}），保留为已确认",
                "warn",
            )
            return False
        if outcome is False:
            log("Camoufox 邮箱租约确认未撤销，保守保留已确认状态", "warn")
            return False
        mailbox_lease_confirmed = False
        return True

    async def prepare_otp(stage_code: str, *, notify_stage: bool = True) -> None:
        if not callable(otp_prepare):
            return
        # Resolve compatibility from the callable signature before invoking
        # it. Catching a TypeError raised by provider code would otherwise
        # replay a side-effecting baseline operation and hide the real bug.
        try:
            signature = inspect.signature(otp_prepare)
        except (TypeError, ValueError):
            # Opaque C-extension callables are rare; preserve the newest
            # contract and let any implementation error propagate once.
            await asyncio.to_thread(
                otp_prepare, stage_code, force_snapshot=True, notify_stage=notify_stage,
            )
            return
        candidates = (
            {"force_snapshot": True, "notify_stage": notify_stage},
            {"force_snapshot": True},
            {},
        )
        for kwargs in candidates:
            try:
                signature.bind(stage_code, **kwargs)
            except TypeError:
                continue
            await asyncio.to_thread(otp_prepare, stage_code, **kwargs)
            return
        raise host.CamoufoxBrowserError(
            stage_code, "准备 Free 邮箱验证码", "邮箱 provider 准备阶段失败",
            error_code=f"{stage_code}_prepare_failed", diagnostic="unsupported_signature",
        )

    async def mark_otp_sent(stage_code: str) -> None:
        if callable(otp_mark_sent):
            await asyncio.to_thread(otp_mark_sent, stage_code)

    def record_profile_timing(state: str, *, terminal_outcome: str = "") -> None:
        """Close profile timing intervals only after an observable outcome."""
        profile_timing.record(
            state,
            submitted=profile_submitted,
            submitted_at=profile_submitted_at,
            async_started_at=profile_async_started_at,
            emit_timing=lambda stage, code, started, outcome: timing_mark(
                "free_camoufox_profile", code, started, outcome,
            ),
            stage_code="free_camoufox_profile",
            terminal_outcome=terminal_outcome,
        )

    def close_profile_timing(outcome: str = "timeout") -> None:
        """Close any pending profile intervals before a terminal failure."""
        profile_timing.close(
            outcome,
            submitted=profile_submitted,
            submitted_at=profile_submitted_at,
            async_started_at=profile_async_started_at,
            emit_timing=lambda stage, code, started, closed: timing_mark(
                "free_camoufox_profile", code, started, closed,
            ),
            stage_code="free_camoufox_profile",
        )

    async def submit_entry_email(selector: str, *, recovery: bool = False, recovery_tag: str = "") -> dict[str, Any]:
        nonlocal entry_form_present, entry_submit_selector, entry_recovery
        nonlocal mailbox_confirmation_abortable
        result = await host._submit_email_form_stable(page, email)
        entry_form_present = bool(result.get("form_present"))
        prepared_input_selector = str(result.get("input_selector") or selector).strip()
        entry_submit_selector = host.clean(
            result.get("submit_selector"), 500,
        )
        if result.get("ok"):
            await confirm_mailbox_before_submit()
            try:
                clicked = await host._click_visible_submit(page, entry_submit_selector)
            except BaseException:
                # The click helper may have dispatched an event before its
                # failure surfaced, so this path is intentionally irreversible.
                mailbox_confirmation_abortable = False
                raise
            if clicked is None:
                # ``None`` means the click call was entered but its outcome is
                # unknown. Do not fall back to Enter or revoke the lease.
                mailbox_confirmation_abortable = False
                raise host.CamoufoxBrowserError(
                    "free_camoufox_signup_email", "填写 Camoufox 注册邮箱",
                    "邮箱提交动作结果不确定，已停止自动回退",
                    error_code="camoufox_email_submit_uncertain",
                    diagnostic=await host._email_submit_uncertain_diagnostic(
                        page,
                        reason="click_outcome_unknown",
                        form_present=entry_form_present,
                        submit_selector=entry_submit_selector,
                    ),
                    safe_page=host._safe_url(page), page_type="entry",
                )
            if clicked:
                mailbox_confirmation_abortable = False
            fallback_input_selector = prepared_input_selector
            if not clicked:
                # The submit control can go stale while React hydrates the
                # form. Re-scan the live DOM before falling back to Enter;
                # using the selector returned by the preparation pass can
                # otherwise target a detached input or the wrong form.
                fresh_selector = await host._wait_for_any_selector(
                    page, EMAIL_SELECTORS, timeout=2,
                )
                if fresh_selector:
                    fallback_input_selector = fresh_selector
                    # Re-apply the value when a new input node replaced the
                    # one used by the preparation script. This also restores
                    # the framework input state before pressing Enter.
                    await host._fill_input_like_user(page, fallback_input_selector, email)
            if not clicked:
                try:
                    entered = await host._submit_visible_form(page, fallback_input_selector)
                except BaseException:
                    mailbox_confirmation_abortable = False
                    raise
                if entered is None:
                    mailbox_confirmation_abortable = False
                    raise host.CamoufoxBrowserError(
                        "free_camoufox_signup_email", "填写 Camoufox 注册邮箱",
                        "邮箱回车提交动作结果不确定，已停止自动回退",
                        error_code="camoufox_email_submit_uncertain",
                        diagnostic=await host._email_submit_uncertain_diagnostic(
                            page,
                            reason="enter_outcome_unknown",
                            form_present=entry_form_present,
                            input_selector=fallback_input_selector,
                        ),
                        safe_page=host._safe_url(page), page_type="entry",
                    )
                if not entered:
                    await abort_mailbox_confirmation_before_submit()
                    raise host.CamoufoxBrowserError(
                        "free_camoufox_signup_email", "填写 Camoufox 注册邮箱",
                        "邮箱表单未能提交", error_code="camoufox_email_submit_failed",
                        diagnostic=json.dumps({
                            "phase": "entry",
                            "reason": "prepared_but_enter_failed",
                            "form_present": entry_form_present,
                            "input_selector": host.clean(fallback_input_selector, 120),
                        }, ensure_ascii=False),
                        safe_page=host._safe_url(page), page_type="entry",
                    )
                mailbox_confirmation_abortable = False
            if not clicked:
                entry_submit_selector = host.clean(fallback_input_selector, 120)
            entry_recovery = recovery_tag or ("form_resubmit" if recovery else entry_recovery)
            log(
                "Camoufox 邮箱表单已提交"
                f"（mode={host.clean(result.get('reason'), 80)}，"
                f"selector={entry_submit_selector or '-'}）",
                "warn" if recovery else "info",
            )
            return result

        # Re-locate before the fallback path as the initial selector may have
        # become detached while the page hydrated.
        fresh_selector = await host._wait_for_any_selector(page, EMAIL_SELECTORS, timeout=2)
        selector = fresh_selector or selector
        if not await host._fill_input_like_user(page, selector, email):
            raise host.CamoufoxBrowserError(
                "free_camoufox_signup_email", "填写 Camoufox 注册邮箱",
                "邮箱输入框写入失败", error_code="camoufox_email_fill_failed",
            )
        await confirm_mailbox_before_submit()
        try:
            entered = await host._submit_visible_form(page, selector)
        except BaseException:
            mailbox_confirmation_abortable = False
            raise
        if entered is None:
            mailbox_confirmation_abortable = False
            raise host.CamoufoxBrowserError(
                "free_camoufox_signup_email", "填写 Camoufox 注册邮箱",
                "邮箱回车提交动作结果不确定，已停止自动回退",
                error_code="camoufox_email_submit_uncertain",
                diagnostic=await host._email_submit_uncertain_diagnostic(
                    page,
                    reason="enter_outcome_unknown",
                    form_present=entry_form_present,
                    input_selector=selector,
                ),
                safe_page=host._safe_url(page), page_type="entry",
            )
        if not entered:
            await abort_mailbox_confirmation_before_submit()
            raise host.CamoufoxBrowserError(
                "free_camoufox_signup_email", "填写 Camoufox 注册邮箱",
                "邮箱表单未能提交", error_code="camoufox_email_submit_failed",
                diagnostic=json.dumps({
                    "phase": "entry",
                    "reason": host.clean(result.get("reason"), 80),
                    "form_present": entry_form_present,
                    "input_selector": host.clean(selector, 120),
                }, ensure_ascii=False),
                safe_page=host._safe_url(page), page_type="entry",
            )
        mailbox_confirmation_abortable = False
        entry_submit_selector = host.clean(selector, 120)
        entry_recovery = recovery_tag or ("form_resubmit" if recovery else entry_recovery)
        fallback = {
            "ok": True,
            "reason": "input_enter_submit",
            "form_present": entry_form_present,
            "input_selector": host.clean(selector, 120),
            "submit_selector": entry_submit_selector,
        }
        log(
            "Camoufox 邮箱表单已使用 Enter 提交"
            f"（selector={entry_submit_selector or '-'}）",
            "warn" if recovery else "info",
        )
        return fallback

    async def entry_diagnostic(
        state: str,
        *,
        navigation_phase: str = "",
        goto_timeout: bool = False,
    ) -> str:
        snapshot = await host._snapshot(page)
        payload = {
            "phase": "entry",
            "submitted": bool(entry_submitted),
            "recovery": entry_recovery,
            "navigation_phase": navigation_phase or entry_recovery or "state_machine",
            "goto_timeout": bool(goto_timeout),
            "observed_page_state": str(state or "unknown"),
            "safe_page": snapshot.get("url"),
            "page_type": state,
            "form_present": bool(entry_form_present),
            "submit_selector": host.clean(entry_submit_selector, 120),
            "title": host.sanitize_failure_text(snapshot.get("title"), 160),
            "sensitive_markers": host._safe_body_markers(snapshot.get("body")),
        }
        return json.dumps(payload, ensure_ascii=False)[:500]

    async def wait_for_state(*states: str, seconds: float = 45.0) -> str:
        grace_remaining = budget_grace_remaining()
        remaining = (
            max(1.0, float(seconds))
            if budget_paused()
            else max(1.0, budget_remaining(), grace_remaining)
        )
        return await host._wait_state(page, min(float(seconds), remaining), *states)

    async def wait_for_otp_input(stage_code: str = "", seconds: float = 45.0) -> tuple[str, str]:
        """Wait for the reference flow's OTP layer without consuming a code.

        ChatGPT can render an intermediate email-verification shell and then
        navigate directly to profile/home while the mailbox provider is still
        waiting.  Polling the DOM alone used to turn that valid transition
        into ``camoufox_otp_input_missing`` and, worse, consumed the code too
        early.  Return the observed page state so the caller can hand control
        back to the main state machine.
        """
        timing_stage = str(stage_code or entry_otp_stage)
        started = time.monotonic()
        end = started + max(1.0, float(seconds))
        if not budget_paused() and not budget_grace_active():
            end = min(current_deadline(), end)
        while time.monotonic() < end:
            current = await host._page_state(page)
            if current not in {"otp", "otp_wait"}:
                timing_mark(timing_stage, "otp_input_ready", started, "state_changed")
                return "", current
            selector = await host._find_visible_selector(page, OTP_SELECTORS)
            if selector:
                timing_mark(timing_stage, "otp_input_ready", started, "success")
                return selector, current
            await asyncio.sleep(0.5)
        timing_mark(timing_stage, "otp_input_ready", started, "timeout")
        return "", await host._page_state(page)

    async def open_registration_entry() -> None:
        """Keep the reference startup gate around only entry navigation."""
        nonlocal entry_submitted, entry_transition_deadline, entry_transition_observe_deadline, entry_transition_started
        nonlocal entry_retry_used, entry_signin_fallback_used, entry_recovery
        # Establish the mailbox baseline before the first request that may
        # send an OTP. The provider itself remains AutoPhone's strategy mode.
        if force_existing_login:
            # Capture the pre-login mailbox baseline without announcing an OTP
            # stage before the page has actually requested authentication.
            await prepare_otp("free_existing_login_otp", notify_stage=False)
        navigation_started = time.monotonic()
        try:
            await host._goto_with_retry(
                page, CHATGPT_LOGIN_URL, timeout_ms=min(timeout * 1000, 90_000),
                proxy_retryable=not force_existing_login, log=log,
            )
        except Exception:
            host.emit_timing(
                timing_fn, "free_camoufox_signup", "camoufox_initial_navigation",
                (time.monotonic() - navigation_started) * 1000, "error",
            )
            raise
        host.emit_timing(
            timing_fn, "free_camoufox_signup", "camoufox_initial_navigation",
            (time.monotonic() - navigation_started) * 1000, "success",
        )
        # The selector may be visible before React has installed the auth
        # shell's delegated submit handler. Match the reference flow's short
        # hydration grace so the first click cannot become a native reload.
        await host._wait_for_entry_hydration(page)
        form_wait_started = time.monotonic()
        email_selector = await host._wait_for_any_selector(page, EMAIL_SELECTORS, timeout=12)
        host.emit_timing(
            timing_fn, "free_camoufox_signup", "camoufox_entry_form_wait",
            (time.monotonic() - form_wait_started) * 1000,
            "success" if email_selector else "timeout",
        )
        if email_selector:
            set_stage("free_existing_login" if force_existing_login else "free_camoufox_signup_email")
            if not force_existing_login:
                await prepare_otp(entry_otp_stage, notify_stage=False)
            await submit_entry_email(email_selector)
            entry_submitted = True
            entry_transition_started = time.monotonic()
            entry_transition_deadline = entry_transition_started + 45.0
            entry_transition_observe_deadline = entry_transition_started + 12.0
            return

        # Keep the same-origin NextAuth fallback from the reference flow for a
        # delayed shell, but never invent an external provider URL.
        if not force_existing_login:
            await prepare_otp(entry_otp_stage, notify_stage=False)
        authorize_url = await host._browser_signin_url(page, email)
        if authorize_url:
            entry_recovery = "same_origin_signin"
            entry_retry_used = True
            entry_signin_fallback_used = True
            await host._goto_with_retry(
                page, authorize_url, timeout_ms=min(timeout * 1000, 90_000),
                proxy_retryable=False, log=log,
            )
            if host._is_chatgpt_entry_url(authorize_url):
                selector = await host._wait_for_any_selector(page, EMAIL_SELECTORS, timeout=8)
                if selector:
                    await submit_entry_email(selector, recovery=True)
            entry_submitted = True
            entry_transition_started = time.monotonic()
            entry_transition_deadline = entry_transition_started + 45.0
            entry_transition_observe_deadline = entry_transition_started + 12.0
            return
        snapshot = await host._snapshot(page)
        raise host.CamoufoxBrowserError(
            "free_camoufox_navigation", "打开 Camoufox 注册页面",
            "登录页未找到邮箱输入框，当前代理返回了不可用页面",
            retryable=True, error_code="camoufox_entry_form_missing",
            diagnostic=json.dumps({
                "safe_page": snapshot.get("url"),
                "title": host.sanitize_failure_text(snapshot.get("title"), 160),
                "page_type": "entry",
            }, ensure_ascii=False)[:500],
            safe_page=snapshot.get("url"), page_type="entry",
        )

    if password_retry:
        return await _finish_password_retry_flow(
            host,
            page,
            email=email,
            password=password,
            config=config,
            controller=controller,
            deadline_fn=current_deadline,
            password_retry_token=password_retry_token,
            otp_callback=otp_callback,
            otp_prepare=otp_prepare,
            otp_mark_sent=otp_mark_sent,
            timing_fn=timing_fn,
            set_stage=set_stage,
        )

    if startup_gate is None:
        await open_registration_entry()
    else:
        async with startup_gate:
            await open_registration_entry()

    while not budget_expired():
        step_count += 1
        if host._stop_requested(config.get("host._stop_requested")):
            raise host.FreeRegisterError(
                "free_run_stop",
                "停止 Free 注册",
                "任务已请求停止，Camoufox 注册已中断",
                retryable=False,
                error_code="free_run_stop",
            )
        # The about-you endpoint can legitimately take close to a minute to
        # finish. Keep a bounded guard, but do not turn that reference-flow
        # wait into an early page-state failure.
        if step_count > max(240, (timeout + 30) * 2):
            raise host.CamoufoxBrowserError(
                "free_camoufox_page_state", "等待 Camoufox 页面状态",
                "注册状态机超出最大推进步数", error_code="camoufox_page_state_limit",
                safe_page=host._safe_url(page), page_type="state_machine",
            )
        state = await host._page_state(page)
        if (
            entry_submitted
            and entry_transition_started
            and not entry_transition_recorded
            and state not in {"entry", "unknown"}
        ):
            host.emit_timing(
                timing_fn,
                "free_camoufox_signup_email",
                "camoufox_entry_transition_wait",
                (time.monotonic() - entry_transition_started) * 1000,
                "success",
            )
            entry_transition_recorded = True
        auth_states = host._POST_ENTRY_AUTH_STATES | {"security"}
        if state in auth_states:
            auth_phase_locked = True
        elif state == "entry" and auth_phase_locked:
            raise host.CamoufoxBrowserError(
                "free_camoufox_navigation", "推进 Camoufox 注册页面",
                "邮箱验证已开始后页面返回邮箱入口，拒绝重复提交",
                retryable=False,
                error_code="camoufox_entry_returned_after_otp",
                diagnostic=await entry_diagnostic(state),
                safe_page=host._safe_url(page), page_type="entry",
            )
        if (
            otp_submitted
            and not otp_transition_recorded
            and state not in {"otp", "otp_wait"}
        ):
            transition_stage = otp_submitted_stage or entry_otp_stage
            if state == "security":
                transition_outcome = "security_challenge"
            elif state in {
                "signup_password", "login_password", "email_verification",
                "profile", "oauth_callback", "home",
            }:
                transition_outcome = "success"
            else:
                # Unknown shells can be transient.  Preserve the timing as a
                # diagnosed transition, but never call it a successful page
                # hand-off.
                transition_outcome = "unexpected_state"
            timing_mark(transition_stage, "otp_submit_transition", otp_submitted_at, transition_outcome)
            otp_transition_recorded = True
        record_profile_timing(state)
        seen[state] = seen.get(state, 0) + 1
        if (
            state not in {"signup_password", "login_password", "otp", "otp_wait", "email_verification", "profile", "security"}
            and seen[state] > _STATE_STUCK_POLLS
        ):
            now = time.monotonic()
            # React navigation can briefly expose an unclassified shell after
            # the submit click. Keep polling both ``entry`` and ``unknown``
            # until the same bounded transition window; otherwise five fast
            # DOM polls (about two seconds) can misclassify an asynchronous
            # navigation as a stuck registration.
            if state in {"entry", "unknown"} and entry_submitted and now < entry_transition_observe_deadline:
                await asyncio.sleep(_STATE_POLL_SECONDS)
                continue
            if state in {"entry", "unknown"} and entry_submitted:
                # A navigation can complete immediately after the polling
                # read above. Re-check once before any recovery action so a
                # verification shell with a stale email form is never
                # mistaken for a failed entry transition.
                refreshed_state = await host._page_state(page)
                if refreshed_state not in {"entry", "unknown"}:
                    seen.clear()
                    await asyncio.sleep(0)
                    continue
            if state == "entry" and entry_submitted and not entry_retry_used and not auth_phase_locked:
                entry_retry_used = True
                entry_recovery = "form_resubmit"
                await prepare_otp(entry_otp_stage, notify_stage=False)
                remaining = max(0.0, entry_transition_deadline - time.monotonic())
                if remaining <= 0.0:
                    continue
                reopened = await host._click_exact_button_text(
                    page, ("Continue", "继续"), timeout=min(3.0, remaining),
                )
                if reopened:
                    log("Camoufox 登录壳回退，已重新打开邮箱表单", "warn")
                remaining = max(0.0, entry_transition_deadline - time.monotonic())
                selector = (
                    await host._wait_for_any_selector(
                        page, EMAIL_SELECTORS, timeout=min(8.0, remaining),
                    )
                    if remaining >= 0.1 else None
                )
                if selector:
                    await submit_entry_email(selector, recovery=True)
                    entry_transition_observe_deadline = min(
                        entry_transition_deadline,
                        time.monotonic() + 12.0,
                    )
                    seen.clear()
                    await asyncio.sleep(_STATE_POLL_SECONDS)
                    continue
                log("Camoufox 登录壳未重新显示邮箱表单，准备同源 signin 兜底", "warn")
            if state == "entry" and entry_submitted and not entry_signin_fallback_used and not auth_phase_locked:
                entry_signin_fallback_used = True
                entry_recovery = "same_origin_signin"
                await prepare_otp(entry_otp_stage, notify_stage=False)
                authorize_url = await host._browser_signin_url(page, email)
                if not authorize_url:
                    raise host.CamoufoxBrowserError(
                        "free_camoufox_navigation", "打开 Camoufox 注册页面",
                        "邮箱已提交，但同源 signin 兜底未返回授权地址",
                        retryable=False,
                        error_code="camoufox_entry_signin_fallback_failed",
                        diagnostic=await entry_diagnostic(state),
                        safe_page=host._safe_url(page), page_type=state,
                    )
                log("Camoufox 登录壳未推进，开始一次同源 signin 兜底", "warn")
                remaining = max(0.0, entry_transition_deadline - time.monotonic())
                if remaining <= 0.0:
                    continue
                try:
                    await host._goto_with_retry(
                        page, authorize_url,
                        # The ordinary 45s entry budget can have less than a
                        # second left after its one allowed form recovery.  A
                        # cross-origin auth document took longer than that in
                        # the retained production trace, so give only this
                        # recovery navigation a bounded 15s dispatch window.
                        timeout_ms=min(
                            timeout * 1000,
                            90_000,
                            max(15_000, int(remaining * 1000)),
                        ),
                        proxy_retryable=False,
                        log=log,
                        # The previous ChatGPT email form remains in the DOM
                        # while auth.openai.com is loading.  It is stale state,
                        # not proof that this navigation is usable.
                        accept_usable_entry=False,
                    )
                except host.CamoufoxBrowserError as exc:
                    if not host._is_navigation_timeout_failure(exc):
                        raise
                    recovered_state = await host._wait_for_post_entry_auth_state(
                        page, timeout=5.0, poll_interval=0.25,
                    )
                    if recovered_state == "security":
                        await host._wait_challenge_then_stop(page, timeout=30)
                        recovered_state = await host._page_state(page)
                    if recovered_state not in host._POST_ENTRY_AUTH_STATES:
                        error_text = await host._auth_error_text(page)
                        raise host.CamoufoxBrowserError(
                            "free_camoufox_navigation", "打开 Camoufox 注册页面",
                            error_text or "邮箱已提交，但 Camoufox 登录入口在限定时间内未跳转",
                            retryable=False,
                            error_code="camoufox_entry_transition_timeout",
                            diagnostic=await entry_diagnostic(
                                recovered_state,
                                navigation_phase="same_origin_signin",
                                goto_timeout=True,
                            ),
                            safe_page=host._safe_url(page),
                            page_type=recovered_state,
                        ) from exc
                    auth_phase_locked = True
                    log(
                        "Camoufox signin 导航等待超时，但页面已进入认证状态，继续状态机",
                        "warn",
                        safe_page=host._safe_url(page),
                        page_type=recovered_state,
                    )
                if host._is_chatgpt_entry_url(authorize_url):
                    selector = await host._wait_for_any_selector(
                        page, EMAIL_SELECTORS,
                        timeout=min(8.0, max(0.1, entry_transition_deadline - time.monotonic())),
                    )
                    if selector:
                        await submit_entry_email(selector, recovery=True)
                entry_transition_observe_deadline = min(
                    entry_transition_deadline,
                    time.monotonic() + 12.0,
                )
                seen.clear()
                await asyncio.sleep(_STATE_POLL_SECONDS)
                continue
            if (
                state == "entry" and entry_submitted
                and entry_retry_used and entry_signin_fallback_used
                and not entry_reload_recovery_used
                and not auth_phase_locked
            ):
                # Both bounded recoveries failed while the shell stayed on the
                # email entry. One full reload of the login page with a final
                # mailbox submission is the last bounded attempt before the
                # terminal transition timeout.
                entry_reload_recovery_used = True
                entry_recovery = "full_reload_signin"
                await prepare_otp(entry_otp_stage, notify_stage=False)
                log("Camoufox 登录壳仍未推进，整页重载登录页做最后一次邮箱提交", "warn")
                remaining = max(0.0, entry_transition_deadline - time.monotonic())
                if remaining <= 0.0:
                    continue
                try:
                    await host._goto_with_retry(
                        page, CHATGPT_LOGIN_URL,
                        timeout_ms=min(timeout * 1000, 90_000, max(15_000, int(remaining * 1000))),
                        proxy_retryable=False, log=log,
                        accept_usable_entry=False,
                    )
                except host.CamoufoxBrowserError as exc:
                    if not host._is_navigation_timeout_failure(exc):
                        raise
                    # A slow reload can still land a usable shell right after
                    # the dispatch timeout; fall through to the selector wait.
                await host._wait_for_entry_hydration(page)
                remaining = max(0.0, entry_transition_deadline - time.monotonic())
                selector = (
                    await host._wait_for_any_selector(
                        page, EMAIL_SELECTORS, timeout=min(8.0, remaining),
                    )
                    if remaining >= 0.1 else None
                )
                if selector:
                    await submit_entry_email(
                        selector, recovery=True, recovery_tag="full_reload_signin",
                    )
                    entry_transition_observe_deadline = min(
                        entry_transition_deadline,
                        time.monotonic() + 12.0,
                    )
                seen.clear()
                await asyncio.sleep(_STATE_POLL_SECONDS)
                continue
            error_text = await host._auth_error_text(page)
            close_profile_timing("unexpected_state")
            raise host.CamoufoxBrowserError(
                "free_camoufox_navigation", "打开 Camoufox 注册页面",
                error_text or (
                    "邮箱已提交，但 Camoufox 登录入口在限定时间内未跳转"
                    if state == "entry" and entry_submitted
                    else "注册页面状态长时间未推进"
                ),
                retryable=not entry_submitted,
                error_code="camoufox_entry_transition_timeout" if state == "entry" and entry_submitted else "camoufox_page_state_stuck",
                diagnostic=await entry_diagnostic(state),
                safe_page=host._safe_url(page), page_type=state,
            )
        if state == "security":
            await host._wait_challenge_then_stop(page, timeout=30)
        if state == "home":
            return await _finish_home_flow(
                host,
                page,
                email=email,
                password=password,
                config=config,
                controller=controller,
                deadline_fn=current_deadline,
                account_flow=account_flow,
                login_password_submitted=login_password_submitted,
                password_used=password_used,
                otp_callback=otp_callback,
                otp_prepare=otp_prepare,
                otp_mark_sent=otp_mark_sent,
                timing_fn=timing_fn,
                set_stage=set_stage,
            )

        if state == "entry":
            if not entry_submitted:
                selector = await host._wait_for_any_selector(page, EMAIL_SELECTORS, timeout=8)
                if selector:
                    set_stage("free_camoufox_signup_email")
                    await prepare_otp(entry_otp_stage, notify_stage=False)
                    await submit_entry_email(selector)
                    entry_submitted = True
                    entry_transition_started = time.monotonic()
                    entry_transition_deadline = entry_transition_started + 45.0
                    entry_transition_observe_deadline = entry_transition_started + 12.0
                else:
                    reopened = await host._click_exact_button_text(
                        page, ("Continue", "继续"), timeout=3,
                    )
                    if reopened:
                        log("Camoufox 登录壳已重新打开邮箱表单", "warn")
            await asyncio.sleep(_STATE_POLL_SECONDS)
            continue

        if state == "login_password":
            if not bool(config.get("existing_account_login", True)):
                raise host.CamoufoxBrowserError(
                    "free_existing_login", "已有 Free 账号登录",
                    "邮箱已存在账号，Camoufox 未开启已有账号邮箱验证码登录",
                    retryable=False, error_code="free_existing_login_disabled",
                )
            account_flow = "existing_login"
            saved_password = str(existing_password or "").strip()
            if not saved_password:
                # Passwordless accounts have no credential to submit. Switch
                # to the login page's verification-code action once; the main
                # loop then continues through the existing_login OTP stage.
                if not passwordless_login_switch_used:
                    passwordless_login_switch_used = True
                    if await host._click_passwordless_login_switch(page):
                        log("已有账号登录未保存密码，已切换为邮箱验证码登录", "warn")
                        seen.clear()
                        await asyncio.sleep(_STATE_POLL_SECONDS)
                        continue
                raise host.CamoufoxBrowserError(
                    "free_existing_login", "已有 Free 账号登录",
                    "已有账号登录缺少已保存密码且未提供验证码登录入口",
                    retryable=False, error_code="free_existing_login_password_missing",
                    safe_page=host._safe_url(page), page_type="login_password",
                )
            set_stage("free_existing_login_password")
            now = time.monotonic()
            if not login_password_submitted:
                if not await host._submit_existing_login_password(page, saved_password):
                    raise host.CamoufoxBrowserError(
                        "free_existing_login", "已有 Free 账号登录",
                        "登录密码页输入或提交失败", retryable=False,
                        error_code="free_camoufox_login_password_page",
                        safe_page=host._safe_url(page), page_type="login_password",
                    )
                login_password_submitted = True
                login_password_submitted_at = time.monotonic()
            else:
                elapsed = now - (login_password_submitted_at or now)
                if elapsed >= 45:
                    raise host.CamoufoxBrowserError(
                        "free_existing_login", "已有 Free 账号登录",
                        "登录密码提交后页面未继续", retryable=False,
                        error_code="free_camoufox_login_password_transition_timeout",
                        safe_page=host._safe_url(page), page_type="login_password",
                    )
                if elapsed >= 12 and not login_password_submit_retried:
                    await host._submit_existing_login_password(page, saved_password)
                    login_password_submit_retried = True
                    log("已有账号登录密码页未跳转，已使用同一密码重试提交", "warn")
            await asyncio.sleep(_STATE_POLL_SECONDS)
            continue

        if state == "email_verification":
            now = time.monotonic()
            if email_verification_started_at <= 0:
                email_verification_started_at = now
                if await host._click_first(page, EMAIL_SUBMIT_SELECTORS, timeout=3):
                    log("邮箱验证页已点击继续", "info")
            elapsed = now - email_verification_started_at
            if elapsed >= 60:
                raise host.CamoufoxBrowserError(
                    "free_email_otp_validate", "验证 Free 邮箱验证码",
                    "邮箱验证页 60 秒未跳转", error_code="camoufox_email_verification_timeout",
                    safe_page=host._safe_url(page), page_type="email_verification",
                )
            if elapsed >= 12 and not email_verification_retried:
                if await host._click_first(page, EMAIL_SUBMIT_SELECTORS, timeout=3):
                    log("邮箱验证页未跳转，已重试点击继续", "warn")
                email_verification_retried = True
            await asyncio.sleep(_SUBMIT_POLL_SECONDS)
            continue

        if state == "signup_password":
            set_stage("free_camoufox_signup_password")
            now = time.monotonic()
            if password_stage_started_at <= 0:
                password_stage_started_at = now
            if now - password_stage_started_at >= 60:
                raise host.CamoufoxBrowserError(
                    "free_camoufox_signup_password", "提交 Camoufox 注册密码",
                    "注册密码页 60 秒未完成", error_code="camoufox_password_stage_timeout",
                    safe_page=host._safe_url(page), page_type="signup_password",
                )
            if password_used:
                elapsed = now - (password_submitted_at or now)
                if elapsed >= 45:
                    raise host.CamoufoxBrowserError(
                        "free_camoufox_signup_password", "提交 Camoufox 注册密码",
                        "注册密码提交后页面未继续", error_code="camoufox_password_transition_timeout",
                        safe_page=host._safe_url(page), page_type="signup_password",
                    )
                if elapsed >= 12 and not password_submit_retried:
                    clicked = await host._click_first(page, PASSWORD_SUBMIT_SELECTORS, timeout=3)
                    if not clicked:
                        selector = await host._find_visible_selector(page, PASSWORD_SELECTORS)
                        if selector:
                            await host._submit_visible_form(page, selector)
                    password_submit_retried = True
                    log("注册密码页未跳转，已使用同一密码重试提交", "warn")
                await asyncio.sleep(_SUBMIT_POLL_SECONDS)
                continue
            selector = await host._wait_for_any_selector(page, PASSWORD_SELECTORS, timeout=15)
            if not selector or not await host._fill_input_like_user(page, selector, password):
                raise host.CamoufoxBrowserError(
                    "free_camoufox_signup_password", "提交 Camoufox 注册密码", "注册密码输入失败",
                    error_code="camoufox_password_fill_failed",
                )
            if not await host._click_first(page, PASSWORD_SUBMIT_SELECTORS, timeout=6):
                await host._submit_visible_form(page, selector)
            password_used = True
            password_submitted_at = time.monotonic()
            await asyncio.sleep(_SUBMIT_POLL_SECONDS)
            continue

        if state in {"otp", "otp_wait"}:
            stage_code = "free_existing_login_otp" if account_flow == "existing_login" else "free_email_otp_wait"
            set_stage(stage_code)
            if not otp_submitted:
                # Match aBaiFreeGPT's email_verification -> otp layering:
                # wait for the actual OTP input before asking the shared
                # mailbox provider for a code.  If the page advances while
                # waiting, let the next state branch handle it.
                selector, observed_state = await wait_for_otp_input(stage_code)
                if observed_state not in {"otp", "otp_wait"}:
                    seen.clear()
                    await asyncio.sleep(0.2)
                    continue
                if not selector:
                    raise host.CamoufoxBrowserError(
                        "free_email_otp_validate", "验证 Free 邮箱验证码", "验证码输入框长时间未出现",
                        error_code="camoufox_otp_input_missing",
                    )
                if entry_submitted or account_flow == "existing_login":
                    await mark_otp_sent(stage_code)
                code = str(await host._await_otp_callback(
                    otp_callback,
                    stage_code,
                    deadline_monotonic=current_deadline(),
                    deadline_controller=controller,
                    stop_requested=config.get("host._stop_requested"),
                ) or "").strip()
                if not code:
                    raise host.CamoufoxBrowserError(
                        "free_email_otp_wait", "等待 Free 邮箱验证码", "未获取到邮箱验证码",
                        error_code="camoufox_otp_missing",
                    )
                current_state = await host._page_state(page)
                if current_state not in {"otp", "otp_wait"}:
                    seen.clear()
                    continue
                otp_submit_started = time.monotonic()
                if not await host._fill_input_like_user(page, selector, code):
                    timing_mark(stage_code, "otp_code_submit", otp_submit_started, "error")
                    current_state = await host._page_state(page)
                    if current_state not in {"otp", "otp_wait"}:
                        seen.clear()
                        continue
                    raise host.CamoufoxBrowserError(
                        "free_email_otp_validate", "验证 Free 邮箱验证码", "验证码输入框不可用",
                        error_code="camoufox_otp_input_missing",
                    )
                otp_input_selector = selector
                if not await host._click_first(page, PASSWORD_SUBMIT_SELECTORS, timeout=6):
                    await host._submit_visible_form(page, selector)
                timing_mark(stage_code, "otp_code_submit", otp_submit_started, "success")
                otp_submitted = True
                otp_submitted_at = time.monotonic()
                otp_submitted_stage = stage_code
                otp_transition_recorded = False
                await asyncio.sleep(_STATE_POLL_SECONDS)
                continue
            elapsed = time.monotonic() - otp_submitted_at
            if elapsed >= 60:
                if otp_resend_used:
                    raise host.CamoufoxBrowserError(
                        "free_email_otp_validate", "验证 Free 邮箱验证码",
                        "验证码提交后页面未继续", error_code="camoufox_otp_transition_timeout",
                    )
                await prepare_otp(stage_code)
                if not await host._click_first(page, RESEND_SELECTORS, timeout=5):
                    snapshot = await host._snapshot(page)
                    raise host.CamoufoxBrowserError(
                        "free_email_otp_validate", "验证 Free 邮箱验证码",
                        "验证码提交后页面未继续，未找到受控重发入口",
                        error_code="camoufox_otp_resend_unavailable",
                        diagnostic=json.dumps(
                            {
                                "safe_page": snapshot.get("url"),
                                "page_type": await host._page_state(page),
                                "title": host.sanitize_failure_text(snapshot.get("title"), 160),
                            },
                            ensure_ascii=False,
                        )[:1000],
                        safe_page=snapshot.get("url"), page_type="otp",
                    )
                await mark_otp_sent(stage_code)
                otp_submitted = False
                otp_submitted_stage = ""
                otp_resend_used = True
                continue
            await asyncio.sleep(_STATE_POLL_SECONDS)
            continue

        if state == "profile":
            set_stage("free_camoufox_profile")
            if not profile_submitted:
                age_value, birthdate = host._reference_age_and_birthdate()
                name_started = time.monotonic()
                name = await host._find_visible_selector(page, NAME_SELECTORS)
                name_filled = False
                if name:
                    name_filled = await host._fill_input_like_user(page, name, host.random_display_name())
                timing_mark(
                    "free_camoufox_profile", "profile_name_fill", name_started,
                    "success" if name_filled else "skipped",
                )
                age_started = time.monotonic()
                age = await host._find_visible_selector(page, AGE_SELECTORS)
                age_filled = False
                if age:
                    # The about-you age control is visible but can be covered by
                    # the page's transition layer. Filling it directly avoids
                    # Playwright's 30s default click timeout; other fields keep
                    # the existing click-first behavior.
                    age_filled = await host._fill_input_like_user(
                        page, age, str(age_value), click=False,
                    )
                timing_mark(
                    "free_camoufox_profile", "profile_age_fill", age_started,
                    "success" if age_filled else "skipped",
                )
                birthday_started = time.monotonic()
                birthday_filled = False
                for birthday_selector in BIRTHDAY_SELECTORS:
                    try:
                        locator = page.locator(birthday_selector).first
                        if await locator.is_visible(timeout=300):
                            birthday_value = str(await locator.input_value(timeout=1000) or "")
                            birthday_filled = bool(birthday_value.strip())
                            if not birthday_filled:
                                await host._fill_input_like_user(page, birthday_selector, birthdate)
                                birthday_filled = True
                            break
                    except Exception:
                        continue
                timing_mark(
                    "free_camoufox_profile", "profile_birthday_fill", birthday_started,
                    "success" if birthday_filled else "skipped",
                )
                hidden_birthday_started = time.monotonic()
                if not birthday_filled:
                    hidden_birthday_filled = await host._sync_hidden_birthday_input(page, birthdate)
                    hidden_outcome = "success" if hidden_birthday_filled else "skipped"
                else:
                    hidden_outcome = "skipped"
                timing_mark(
                    "free_camoufox_profile", "profile_birthday_hidden_sync", hidden_birthday_started,
                    hidden_outcome,
                )
                consent_started = time.monotonic()
                consent_accepted = await host._accept_about_you_consents(page, log)
                timing_mark(
                    "free_camoufox_profile", "profile_consent", consent_started,
                    "success" if consent_accepted else "skipped",
                )
                submit_wait_started = time.monotonic()
                submit_selector = await host._wait_for_submit_enabled(page, PROFILE_SUBMIT_SELECTORS, timeout=25)
                timing_mark(
                    "free_camoufox_profile", "profile_submit_button_wait", submit_wait_started,
                    "success" if submit_selector else "error",
                )
                if not submit_selector:
                    raise host.CamoufoxBrowserError(
                        "free_camoufox_profile", "填写 Camoufox 账号资料",
                        "资料页提交按钮长时间不可用", error_code="camoufox_profile_submit_unavailable",
                    )
                submit_click_started = time.monotonic()
                clicked = await host._click_first(page, (submit_selector,), timeout=8)
                timing_mark(
                    "free_camoufox_profile", "profile_submit_click", submit_click_started,
                    "success" if clicked else "not_confirmed",
                )
                profile_submitted = True
                profile_submitted_at = time.monotonic()
                # Start the diagnostic async interval after the optional
                # birthday confirmation.  This keeps the modal's own timing
                # out of the network/page-transition measurement.
                profile_timing = ProfileTimingTracker()
                birthday_modal_started = time.monotonic()
                birthday_confirmed = await host._confirm_birthday(page, log, timeout=5)
                timing_mark(
                    "free_camoufox_profile", "profile_birthday_modal", birthday_modal_started,
                    "success" if birthday_confirmed else "skipped",
                )
                profile_async_started_at = time.monotonic()
            else:
                # Match aBaiFreeGPT: submitting about-you is an asynchronous
                # account-creation request. Keep the page alive for 60s,
                # confirm any birthday modal, then allow one more form fill
                # instead of classifying a still-loading page as navigation
                # failure.
                elapsed = time.monotonic() - (profile_submitted_at or time.monotonic())
                if elapsed >= 60:
                    timing_mark(
                        "free_camoufox_profile", "profile_async_submit_wait",
                        profile_async_started_at or profile_submitted_at, "timeout",
                    )
                    profile_submitted = False
                    profile_submitted_at = 0.0
                    profile_async_started_at = 0.0
                    log("Camoufox 资料页提交后 60 秒未跳转，允许重新填写重试", "warn")
                else:
                    await host._confirm_birthday(page, log, timeout=0.5)
                    await asyncio.sleep(_STATE_POLL_SECONDS)
                    continue
            await asyncio.sleep(_STATE_POLL_SECONDS)
            continue

        if state == "oauth_callback":
            await asyncio.sleep(_STATE_POLL_SECONDS)
            continue

        if state == "external_auth":
            close_profile_timing("unexpected_state")
            snapshot = await host._snapshot(page)
            raise host.CamoufoxBrowserError(
                "free_camoufox_navigation", "打开 Camoufox 注册页面",
                "注册入口误进入外部 OAuth 登录页；已停止自动操作",
                retryable=False, error_code="camoufox_unexpected_external_auth",
                diagnostic=json.dumps({
                    "safe_page": snapshot.get("url"),
                    "title": host.sanitize_failure_text(snapshot.get("title"), 160),
                    "page_type": "external_auth",
                }, ensure_ascii=False)[:500],
                safe_page=snapshot.get("url"), page_type="external_auth",
            )

        if state == "security":
            snapshot = await host._snapshot(page)
            raise host.CamoufoxBrowserError(
                "free_camoufox_challenge", "等待 Camoufox 安全验证",
                "注册流程进入安全验证，已停止自动操作", retryable=False,
                error_code="free_camoufox_security_challenge",
                diagnostic=json.dumps({
                    "safe_page": snapshot.get("url"),
                    "page_type": "security",
                    "sensitive_markers": host._safe_body_markers(snapshot.get("body")),
                }, ensure_ascii=False)[:500],
                safe_page=snapshot.get("url"), page_type="security",
            )
        error_text = await host._auth_error_text(page)
        if error_text:
            close_profile_timing("error")
            raise host.CamoufoxBrowserError(
                "free_camoufox_navigation", "打开 Camoufox 注册页面", error_text,
                retryable=not entry_submitted, error_code="camoufox_auth_page_error",
                safe_page=host._safe_url(page), page_type=state,
            )
        await asyncio.sleep(_STATE_POLL_SECONDS)

    # If the global deadline expires while the about-you request is still
    # pending, close any open timing intervals before returning the failure.
    close_profile_timing("timeout")
    raise host.CamoufoxBrowserError(
        "free_camoufox_page_state", "确认 ChatGPT 登录首页",
        "注册状态机超时，页面未确认进入首页", error_code="camoufox_home_not_confirmed",
        safe_page=host._safe_url(page), page_type=await host._page_state(page),
    )


# The registration state machine is consumed through the free_camoufox_runtime
# facade; no public names are exported here.
__all__: list[str] = []
