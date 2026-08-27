"""Credential-safe timing labels shared by Free runtime adapters.

Timing records deliberately contain only stable codes, labels, durations and
outcomes.  They are suitable for the task snapshot and diagnostic UI without
carrying mailbox URLs, OTP values, page text or proxy credentials.
"""

from __future__ import annotations

from typing import Any, Callable


# Keep this allow-list small and explicit.  A caller cannot accidentally turn
# a secret-shaped value into a public timing field.
FREE_TIMING_SUBSTEPS: dict[str, str] = {
    # Mailbox OTP request and recognition milestones.
    "mailbox_baseline": "邮箱请求前基线",
    "mailbox_poll_scan": "邮箱轮询扫描",
    "mailbox_detail_refresh": "邮箱详情刷新",
    "mailbox_provider_refresh": "邮箱服务刷新",
    "mailbox_first_listing": "首次看到邮箱列表",
    "mailbox_first_openai": "首次看到 OpenAI 邮件",
    "mailbox_first_code": "首次识别到新验证码",
    "mailbox_resend": "邮箱验证码受控重发",
    "mailbox_final_fallback": "邮箱最终兜底扫描",
    # OTP page hand-off after the mailbox code is returned.
    "otp_input_ready": "OTP 输入框就绪",
    "otp_code_submit": "OTP 填写并提交",
    "otp_submit_transition": "OTP 提交后页面切换",
    # The ten profile actions requested for Camoufox diagnosis.
    "profile_name_fill": "资料页填写姓名",
    "profile_age_fill": "资料页填写年龄",
    "profile_birthday_fill": "资料页填写生日",
    "profile_birthday_hidden_sync": "资料页同步隐藏生日字段",
    "profile_consent": "资料页接受隐私条款",
    "profile_submit_button_wait": "等待资料提交按钮可用",
    "profile_submit_click": "点击资料提交",
    "profile_birthday_modal": "确认生日弹窗",
    "profile_async_submit_wait": "等待资料异步提交",
    "profile_home_state_wait": "等待 home/认证状态",
}


TimingCallback = Callable[[str, str, int, str], Any]


def emit_timing(
    callback: TimingCallback | None,
    stage_code: str,
    code: str,
    elapsed_ms: Any,
    outcome: str = "success",
) -> None:
    """Best-effort emission for adapter code paths.

    Timing must never change the registration outcome.  The manager validates
    the allow-list again before persistence, while this helper keeps old
    third-party callbacks callable by swallowing callback-side failures.
    """
    if not callable(callback) or code not in FREE_TIMING_SUBSTEPS:
        return
    try:
        value = max(0, int(elapsed_ms))
    except (TypeError, ValueError):
        return
    try:
        callback(str(stage_code or ""), code, value, str(outcome or "success"))
    except Exception:
        return


__all__ = ["FREE_TIMING_SUBSTEPS", "TimingCallback", "emit_timing"]
