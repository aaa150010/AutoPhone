"""Mailbox wait-code family delegated out of ``web_gui``.

Every callable receives the hosting ``web_gui`` module as its first ``host``
argument and resolves web-owned helpers, saved ``_ORIGINAL_*`` methods and
runtime singletons through it at call time, so existing ``web_gui.<name>``
patching in tests and integrations keeps the original late-bound semantics.
"""

from __future__ import annotations

import chatgpt_totp as _chatgpt_totp_ext
import mailbox_otp_service as _mailbox_otp_service_ext
import manual_verification_runtime as _manual_verification_runtime_ext
import oauth_mfa_runtime as _oauth_mfa_runtime_ext


def automatic_url_mailbox_wait_code(host, self, email):
    entry = getattr(self, "entry", None)
    if (
        getattr(entry, "oauth_client_id", "") == "chatgpt_totp"
        and getattr(entry, "oauth_refresh_token", "")
        and getattr(self, "_chatgpt_email_otp_verified", False)
    ):
        code = _chatgpt_totp_ext.totp_code(getattr(entry, "oauth_refresh_token", ""))
        _mailbox_otp_service_ext.finish_runtime_request(getattr(self, "provider", None))
        host._call_log(getattr(self, "log_fn", None), "  [Codex] 已根据 2FA 密钥生成临时验证码", "info")
        return code
    provider = getattr(self, "provider", None)
    max_poll_attempts = host._int_value(
        getattr(self, "max_attempts", 30),
        30,
        minimum=1,
        maximum=1000,
    )
    timeout_seconds = host._int_value(getattr(self, "timeout", 90), 90, minimum=1, maximum=600)
    interval_seconds = host._int_value(getattr(self, "interval", 5), 5, minimum=1, maximum=60)
    deadline = getattr(self, "_gptphone_email_code_deadline", None)
    code = _mailbox_otp_service_ext.legacy_wait_code(
        self,
        email,
        wait_fn=getattr(host, "_ORIGINAL_URL_MAILBOX_WAIT_CODE"),
        max_poll_attempts=max_poll_attempts,
        timeout_seconds=timeout_seconds,
        interval_seconds=interval_seconds,
        deadline_monotonic=float(deadline) if deadline is not None else None,
    )
    if code:
        setattr(self, "_chatgpt_email_otp_verified", True)
        if (
            getattr(entry, "oauth_client_id", "") == "chatgpt_totp"
            and getattr(entry, "oauth_refresh_token", "")
        ):
            host._MAILBOX_TOTP_SECRET_CONTEXT.set(str(getattr(entry, "oauth_refresh_token", "") or ""))
    return code


def automatic_outlook_mailbox_wait_code(host, self, email):
    used_codes = set(getattr(self, "_gptphone_used_email_otp_codes", ()) or ())
    poller = getattr(self, "poller", None)
    original_poll_code = getattr(poller, "poll_code", None)
    restore_instance_override = False
    previous_instance_override = None

    if used_codes and callable(original_poll_code):
        poller_vars = getattr(poller, "__dict__", {})
        restore_instance_override = "poll_code" in poller_vars
        previous_instance_override = poller_vars.get("poll_code")

        def poll_distinct_code(*args, **kwargs):
            excluded = set(kwargs.get("exclude_codes") or ())
            excluded.update(used_codes)
            kwargs["exclude_codes"] = excluded
            return original_poll_code(*args, **kwargs)

        poller.poll_code = poll_distinct_code
        host._call_log(
            getattr(self, "log_fn", None),
            "  [邮箱取码诊断/email_code_waiting] 重发后已排除本任务上一轮验证码，等待新邮件",
            "info",
        )

    try:
        code = getattr(host, "_ORIGINAL_OUTLOOK_OTP_WAIT_CODE")(self, email)
    finally:
        if used_codes and callable(original_poll_code):
            if restore_instance_override:
                poller.poll_code = previous_instance_override
            else:
                del poller.poll_code

    normalized = str(code or "").strip()
    if normalized:
        used_codes.add(normalized)
        self._gptphone_used_email_otp_codes = used_codes
    return code


def manual_task_generation(host, task_id):
    free_manager = getattr(host, "_FREE_REGISTER", None)
    if free_manager is not None:
        try:
            task = next(
                item for item in free_manager.public_tasks()
                if str(item.get("task_id") or "") == str(task_id or "").strip()
            )
            return int(free_manager._manual_generation(str(task_id)))
        except (StopIteration, TypeError, ValueError, AttributeError):
            pass
    return _oauth_mfa_runtime_ext.task_generation(task_id, host._AUTH_SESSIONS.public_snapshot)


def manual_email_wait(host, provider, email, automatic_wait, *, parser_provider=None):
    # The recovered call sites (and older integrations) use the historic
    # three-argument helper signature.  Infer the URL parser owner from the
    # wrapper provider when the optional context is omitted so those callers
    # remain compatible while still recording parser samples.
    if parser_provider is None:
        parser_provider = getattr(provider, "provider", None)
    task_id = str(host._TASK_CONTEXT.get() or getattr(provider, "task_id", "") or "").strip()
    if not task_id:
        return automatic_wait()
    timeout = host._int_value(getattr(provider, "timeout", 90), 90, minimum=1, maximum=600)
    return _manual_verification_runtime_ext.wait_with_manual_fallback(
        automatic_wait,
        broker=host._MANUAL_VERIFICATION,
        task_id=task_id,
        input_kind="email_otp",
        generation=manual_task_generation(host, task_id),
        stop_event=_oauth_mfa_runtime_ext.provider_stop_event(provider),
        automatic_timeout_seconds=timeout,
        manual_timeout_seconds=_manual_verification_runtime_ext.DEFAULT_WINDOW_SECONDS,
        on_automatic_unmatched=(
            lambda cause: _mailbox_otp_service_ext.record_runtime_parser_sample(
                parser_provider,
                cause,
            )
        ) if parser_provider is not None else None,
        on_manual_selected=lambda: host._call_log(
            getattr(provider, "log_fn", None),
            "  [人工邮箱验证码/email_code_waiting] 已接收当前任务的人工验证码",
            "info",
        ),
    )


def url_mailbox_wait_code(host, self, email):
    _oauth_mfa_runtime_ext.remember_provider_totp_secret(
        self, host._TASK_TOTP_SECRETS, current_task_get=host._TASK_CONTEXT.get,
    )
    return host._manual_email_wait(
        self,
        email,
        lambda: host._automatic_url_mailbox_wait_code(self, email),
    )


def outlook_mailbox_wait_code(host, self, email):
    _oauth_mfa_runtime_ext.remember_provider_totp_secret(
        self, host._TASK_TOTP_SECRETS, current_task_get=host._TASK_CONTEXT.get,
    )
    return host._manual_email_wait(
        self,
        email,
        lambda: host._automatic_outlook_mailbox_wait_code(self, email),
    )


def gptmail_mailbox_wait_code(host, self, email):
    return host._manual_email_wait(
        self,
        email,
        lambda: getattr(host, "_ORIGINAL_GPTMAIL_OTP_WAIT_CODE")(self, email),
    )


__all__ = [
    "automatic_url_mailbox_wait_code",
    "automatic_outlook_mailbox_wait_code",
    "manual_email_wait",
    "manual_task_generation",
    "url_mailbox_wait_code",
    "outlook_mailbox_wait_code",
    "gptmail_mailbox_wait_code",
]
