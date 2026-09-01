"""Optional Camoufox browser driver for the Free registration workflow.

Camoufox is deliberately imported lazily so the protocol driver remains usable
when the optional browser package is absent.
The browser pool owns only browser/context lifecycle; mailbox, result and
failure semantics stay in the Free runtime and shared account service.
"""

from __future__ import annotations

import asyncio
import atexit
from concurrent.futures import (
    CancelledError as FutureCancelledError,
    TimeoutError as FutureTimeoutError,
)
from dataclasses import dataclass
from datetime import date
import inspect
import json
import math
import os
from pathlib import Path
import random
import re
import shutil
import tempfile
import threading
import time
import traceback
from collections import deque
from typing import Any, Callable, Deque, Mapping
from urllib.parse import unquote, urlsplit, urlencode
import uuid

try:
    from .free_account_service import (
        CHATGPT_ACCOUNTS_URL,
        CHATGPT_ELIGIBILITY_URL,
        browser_add_password,
        browser_json_fetch,
        browser_plan_details,
        browser_session,
        browser_twofa,
        finalize_registration_result,
        password_retry_allowed,
        plan_details_from_payloads,
    )
    from .free_register_common import (
        FIXED_PASSWORD,
        FreeRegisterError,
        configured_free_password,
        clean,
        fingerprint,
        random_birthdate,
        random_display_name,
        proxy_transport_config,
        safe_log_message,
    )
    from .free_failure_runtime import merge_account_result_fields, sanitize_failure_text
    from .free_mailbox_otp import build_free_mailbox_otp_provider
    from .free_proxy_bridge import Socks5HttpBridge
    from .free_timing import TimingCallback, emit_timing
except ImportError:  # pragma: no cover - top-level recovery import
    from free_account_service import (  # type: ignore[no-redef]
        CHATGPT_ACCOUNTS_URL, CHATGPT_ELIGIBILITY_URL, browser_json_fetch,
        browser_add_password,
        browser_plan_details, browser_session, browser_twofa, finalize_registration_result,
        password_retry_allowed, plan_details_from_payloads,
    )
    from free_register_common import (  # type: ignore[no-redef]
        FIXED_PASSWORD, FreeRegisterError, configured_free_password, clean, random_birthdate, random_display_name,
        fingerprint, proxy_transport_config,
        safe_log_message,
    )
    from free_failure_runtime import merge_account_result_fields, sanitize_failure_text  # type: ignore[no-redef]
    from free_mailbox_otp import build_free_mailbox_otp_provider  # type: ignore[no-redef]
    from free_proxy_bridge import Socks5HttpBridge  # type: ignore[no-redef]
    from free_timing import TimingCallback, emit_timing  # type: ignore[no-redef]


CHATGPT_LOGIN_URL = "https://chatgpt.com/auth/login"
EMAIL_SELECTORS = (
    "input#login-email", "input[type='email']", "input[name='email']",
    "input[name='username']", "input[autocomplete='username']",
    "input[autocomplete*='username']", "input[autocomplete*='email']",
    "input[inputmode='email']", "input[id*='email' i]",
)
OTP_SELECTORS = (
    "input[autocomplete='one-time-code']", "input[inputmode='numeric']",
    "input[type='tel']", "input[name*='code' i]", "input[id*='code' i]",
)
PASSWORD_SELECTORS = (
    "input[type='password']", "input[name='password']", "input[name*='password' i]",
    "input[autocomplete='new-password']",
)
LOGIN_PASSWORD_SELECTORS = (
    "input[autocomplete='current-password']", "input[type='password']",
    "input[name='password']", "input[name*='password' i]",
)
NAME_SELECTORS = (
    "input[name='name']", "input[name='full_name']", "input[autocomplete='name']",
    "input[id*='name' i]", "input[placeholder*='name' i]",
)
BIRTHDAY_SELECTORS = (
    "input[name='birthday']", "input[type='date']", "input[name='birthdate']",
    "input[name='birth_date']", "input[autocomplete='bday']",
    "input[id*='birth' i]", "input[placeholder*='birth' i]",
)
AGE_SELECTORS = (
    "input[name='age']", "input[type='number'][name*='age' i]",
    "input[placeholder*='age' i]", "input[id*='age' i]",
)
EMAIL_SUBMIT_SELECTORS = (
    "button[type='submit']", "input[type='submit']", "button[data-testid='continue-button']",
    "button:has-text('Continue')", "button:has-text('continue')", "button:has-text('Next')",
    "button:has-text('Sign up')", "button:has-text('sign up')",
    "button:has-text('创建账号')", "button:has-text('注册')",
)
PASSWORD_SUBMIT_SELECTORS = (
    "button[type='submit']", "input[type='submit']", "button[data-testid='continue-button']",
    "button:has-text('Continue')", "button:has-text('continue')",
    "button:has-text('Create account')", "button:has-text('create account')",
    "button:has-text('Sign up')", "button:has-text('创建账号')", "button:has-text('注册')",
)
PASSWORDLESS_SELECTORS = (
    "a[href*='passwordless']", "button:has-text('email code')",
    "button:has-text('Email code')", "button:has-text('Use email')",
    "a:has-text('Use email')", "button:has-text('邮箱验证码')",
)
LOGIN_PASSWORD_SUBMIT_SELECTORS = (
    "button[type='submit']", "input[type='submit']",
    "button[data-testid='continue-button']",
    "button:has-text('Continue')", "button:has-text('continue')",
    "button:has-text('Sign in')", "button:has-text('sign in')",
    "button:has-text('Log in')", "button:has-text('log in')",
    "button:has-text('登录')", "button:has-text('登入')",
)
RESEND_SELECTORS = (
    "button:has-text('Resend')", "button:has-text('resend')",
    "button:has-text('重新发送')", "button:has-text('重发')",
    "a[href*='resend' i]", "[role='button']:has-text('Resend')",
)
PROFILE_SUBMIT_SELECTORS = (
    "button[type='submit']", "button[data-testid='continue-button']",
    "button:has-text('Continue')", "button:has-text('Sign up')",
    "button:has-text('Create account')", "button:has-text('完成')",
)


class CamoufoxDependencyError(FreeRegisterError):
    def __init__(self, detail: str = "") -> None:
        super().__init__(
            "free_camoufox_dependency", "检查 Camoufox 依赖",
            "Camoufox 未安装或运行时不可用" + (f"（{clean(detail, 180)}）" if detail else ""),
            retryable=False,
            error_code="camoufox_dependency_missing",
            action_hint="安装 camoufox 及其浏览器运行时后重新执行 Free 预检",
        )


def _profile_transition_timing_outcome(state: str) -> str:
    """Return a public timing outcome for an about-you page transition.

    Only the states that prove the request was accepted by the auth flow are
    successful.  In particular, a security challenge or an unknown shell must
    never be presented as a successful profile submission.
    """
    normalized = str(state or "").strip().lower()
    if normalized in {"home", "oauth_callback"}:
        return "success"
    if normalized == "security":
        return "security_challenge"
    return "unexpected_state"


class CamoufoxBrowserError(FreeRegisterError):
    pass


# Manual verification is deliberately bounded.  A registration can encounter
# one entry OTP plus independent password and 2FA OTPs, so pool watchdogs
# reserve room for all three windows and a short post-submit handoff.
MANUAL_OTP_WINDOW_SECONDS = 300
MANUAL_OTP_HANDOFF_GRACE_SECONDS = 2.0
MANUAL_OTP_POST_SUBMIT_GRACE_SECONDS = 30.0
MAX_MANUAL_OTP_WINDOWS = 3

_DEADLINE_CONTROLLER_MISSING = object()


def _deadline_controller_call(
    controller: Any,
    name: str,
    *args: Any,
    default: Any = _DEADLINE_CONTROLLER_MISSING,
) -> Any:
    """Invoke an optional controller hook without making it a failure node."""
    if controller is None:
        return default
    try:
        method = getattr(controller, name, None)
        if not callable(method):
            return default
        return method(*args)
    except Exception:
        # Older recovered adapters can expose only a partial controller. The
        # absolute monotonic deadline remains the compatibility fallback.
        return default


def _deadline_controller_bool(controller: Any, name: str) -> bool:
    value = _deadline_controller_call(controller, name, default=False)
    try:
        return bool(value)
    except Exception:
        return False


class RegistrationDeadline:
    """A monotonic registration budget that can pause for manual OTP input.

    The controller is intentionally in-memory and owned by one registration
    invocation.  While paused, ``remaining`` is frozen and ``is_expired`` is
    false; resuming shifts the absolute deadline by the time spent in the
    manual window.  This lets the browser flow, its worker watchdog and the
    mailbox provider observe one budget without extending ordinary waits.
    """

    def __init__(
        self,
        timeout_seconds: float,
        *,
        monotonic_fn: Callable[[], float] = time.monotonic,
    ) -> None:
        self._monotonic = monotonic_fn
        now = float(monotonic_fn())
        try:
            timeout = max(0.0, float(timeout_seconds))
        except (TypeError, ValueError):
            timeout = 0.0
        self._deadline = now + timeout
        self._paused_at: float | None = None
        self._paused_remaining = 0.0
        self._last_outcome = ""
        self._manual_prompt_active = False
        self._manual_handoff_until = 0.0
        self._post_submit_grace_until = 0.0
        self._otp_wait_depth = 0
        self._lock = threading.RLock()

    def is_paused(self) -> bool:
        with self._lock:
            return self._paused_at is not None

    def remaining(self) -> float:
        with self._lock:
            if self._paused_at is not None:
                return max(0.0, self._paused_remaining)
            return max(0.0, self._deadline - float(self._monotonic()))

    def deadline(self) -> float:
        with self._lock:
            return float(self._deadline)

    def is_expired(self) -> bool:
        with self._lock:
            return self._paused_at is None and self._deadline <= float(self._monotonic())

    def begin_otp_wait(self) -> None:
        """Mark a task-scoped OTP callback as active for watchdog handoff."""
        with self._lock:
            self._otp_wait_depth += 1

    def end_otp_wait(self) -> None:
        with self._lock:
            self._otp_wait_depth = max(0, self._otp_wait_depth - 1)

    def otp_wait_active(self) -> bool:
        with self._lock:
            return self._otp_wait_depth > 0

    def request_manual_handoff(self) -> None:
        """Pause briefly so an OTP worker can open its manual prompt."""
        with self._lock:
            self._pause_manual_locked()
            self._manual_handoff_until = max(
                self._manual_handoff_until,
                float(self._monotonic()) + MANUAL_OTP_HANDOFF_GRACE_SECONDS,
            )

    def manual_handoff_active(self) -> bool:
        with self._lock:
            return self._manual_handoff_until > float(self._monotonic())

    def manual_handoff_remaining(self) -> float:
        """Return the remaining short scheduling handoff allowance."""
        with self._lock:
            return max(0.0, self._manual_handoff_until - float(self._monotonic()))

    def manual_prompt_opened(self) -> None:
        """Record that the broker prompt is visible to the operator."""
        with self._lock:
            self._pause_manual_locked()
            self._manual_prompt_active = True
            self._manual_handoff_until = 0.0

    def manual_prompt_active(self) -> bool:
        with self._lock:
            return bool(self._manual_prompt_active)

    def manual_submission_grace_active(self) -> bool:
        with self._lock:
            return self._post_submit_grace_until > float(self._monotonic())

    def manual_submission_grace_remaining(self) -> float:
        """Return the finite post-submit handoff allowance, if any."""
        with self._lock:
            return max(0.0, self._post_submit_grace_until - float(self._monotonic()))

    def _pause_manual_locked(self) -> None:
        if self._paused_at is not None:
            return
        now = float(self._monotonic())
        self._paused_at = now
        self._paused_remaining = max(0.0, self._deadline - now)

    def pause_manual(self) -> None:
        with self._lock:
            self._pause_manual_locked()

    def resume_manual(self, outcome: str = "") -> None:
        with self._lock:
            paused_at = self._paused_at
            if paused_at is None:
                return
            now = float(self._monotonic())
            # Preserve the exact budget left at prompt open and add back the
            # elapsed manual interval, including an interval that crossed the
            # original deadline.
            self._deadline = now + max(0.0, self._paused_remaining)
            self._paused_at = None
            self._paused_remaining = 0.0
            self._manual_prompt_active = False
            self._manual_handoff_until = 0.0
            normalized_outcome = str(outcome or "")[:32]
            self._last_outcome = normalized_outcome
            # If the prompt opened after the active budget had already
            # reached zero, let the submitted code traverse the page/API
            # handoff before the watchdog reports a real timeout. This grace
            # is finite and applies only to an actually consumed submission.
            self._post_submit_grace_until = (
                now + MANUAL_OTP_POST_SUBMIT_GRACE_SECONDS
                if normalized_outcome == "submitted" and self._deadline <= now
                else 0.0
            )

    def sync_manual_prompt(self, prompt: Mapping[str, Any] | None = None) -> None:
        """Synchronize an optional broker prompt without requiring a broker.

        The provider invokes ``pause_manual``/``resume_manual`` directly. This
        helper exists for watchdogs and compatibility adapters that can expose
        a public prompt snapshot; it is deliberately conservative and never
        opens or closes a prompt itself.
        """
        if isinstance(prompt, Mapping) and str(prompt.get("input_kind") or "") == "email_otp":
            phase = str(prompt.get("phase") or "manual").casefold()
            if phase == "manual":
                self.manual_prompt_opened()


# Name used by a few recovered integrations and focused tests.
_RegistrationDeadlineController = RegistrationDeadline


_BROWSER_PROCESS_LOST_MARKERS = (
    "target page, context or browser has been closed",
    "browser has been closed",
    "browser closed",
    "browser disconnected",
    "target closed",
    "connection closed while reading from the driver",
    "playwright connection closed",
)

_PROXY_BLOCK_PAGE_MARKERS = (
    "unable to load site",
    "if you are using a vpn",
    "try turning it off",
    "this website is using a security service",
    "access denied",
    "sorry, you have been blocked",
    "web proxy blocked",
    "proxy blocked",
    "代理被阻断",
    "代理阻断",
)

_TRANSIENT_NAV_MARKERS = (
    "err_connection_closed",
    "err_connection_reset",
    "err_connection_refused",
    "err_connection_aborted",
    "err_connection_failed",
    "err_timed_out",
    "err_network_changed",
    "err_empty_response",
    "err_socks_connection_failed",
    "err_proxy_connection_failed",
    # Firefox/Camoufox reports the same transport failures with NS_ERROR
    # names instead of Chromium's ERR_* names.
    "ns_error_connection_closed",
    "ns_error_connection_reset",
    "ns_error_connection_refused",
    "ns_error_net_timeout",
    "ns_error_unknown_host",
    "ns_error_proxy_connection_refused",
    "connection refused",
    "connection reset",
    "navigation timeout",
    "page.goto: timeout",
    "timed out",
)


def _browser_process_lost(exc: BaseException) -> bool:
    message = str(exc or "").casefold()
    return any(marker in message for marker in _BROWSER_PROCESS_LOST_MARKERS)


def _is_transient_navigation_error(exc: BaseException) -> bool:
    """Match the reference flow's transport-only navigation retry boundary."""
    message = str(exc or "").casefold()
    return any(marker in message for marker in _TRANSIENT_NAV_MARKERS)


def _navigation_failure_category(exc: BaseException) -> str:
    if _browser_process_lost(exc):
        return "browser_process_lost"
    if "timeout" in str(exc or "").casefold() or "timed out" in str(exc or "").casefold():
        return "navigation_timeout"
    if _is_transient_navigation_error(exc):
        return "navigation_transient"
    return "navigation_error"


def _navigation_failure_reason(exc: BaseException) -> str:
    message = str(exc or "").casefold()
    if any(marker in message for marker in ("ns_error_connection_refused", "err_connection_refused", "connection refused")):
        return "connection_refused"
    if any(marker in message for marker in ("ns_error_connection_reset", "err_connection_reset", "connection reset")):
        return "connection_reset"
    if any(marker in message for marker in ("ns_error_net_timeout", "err_timed_out", "timed out", "navigation timeout")):
        return "timeout"
    if any(marker in message for marker in ("ns_error_unknown_host", "err_name_not_resolved")):
        return "name_resolution"
    if any(marker in message for marker in ("err_proxy_connection_failed", "ns_error_proxy_connection_refused")):
        return "proxy_connection_failed"
    return ""


def _navigation_diagnostic(exc: BaseException, page: Any) -> str:
    """Return a small, stable diagnostic without persisting exception text."""
    category = _navigation_failure_category(exc)
    exception_type = type(exc).__name__[:80] or "UnknownError"
    safe_page = _safe_url(page)
    reason = _navigation_failure_reason(exc)
    reason_field = f"; reason={reason}" if reason else ""
    return f"category={category}; exception_type={exception_type}{reason_field}; safe_page={safe_page}"


def _mark_recycle_required(error: BaseException, reason: str = "") -> BaseException:
    """Attach browser-pool recovery intent without widening the public schema."""
    try:
        setattr(error, "recycle_required", True)
        if reason:
            setattr(error, "recycle_reason", clean(reason, 240))
    except Exception:
        pass
    return error


def _load_camoufox_api() -> tuple[Any, Any]:
    try:
        from camoufox.async_api import AsyncCamoufox, AsyncNewContext
    except Exception as exc:  # pragma: no cover - environment dependent
        raise CamoufoxDependencyError(type(exc).__name__) from exc
    return AsyncCamoufox, AsyncNewContext


def _check_camoufox_runtime() -> str:
    """Require the browser binary, not only the optional Python package."""
    try:
        from camoufox.pkgman import installed_verstr
    except Exception as exc:  # pragma: no cover - package-version dependent
        raise CamoufoxDependencyError(type(exc).__name__) from exc
    try:
        version = str(installed_verstr() or "").strip()
    except Exception as exc:  # pragma: no cover - environment dependent
        raise CamoufoxDependencyError(type(exc).__name__) from exc
    if not version:
        raise CamoufoxDependencyError("browser runtime unavailable")
    return version


def _camoufox_error_detail(exc: BaseException) -> str:
    """Keep nested launch diagnostics while applying the normal redaction."""
    parts: list[str] = []
    current: BaseException | None = exc
    seen: set[int] = set()
    while current is not None and id(current) not in seen and len(parts) < 3:
        seen.add(id(current))
        error_code = str(getattr(current, "error_code", "") or "").strip()
        diagnostic = str(getattr(current, "diagnostic", "") or "").strip()
        # Exception messages can contain page text or provider payloads.  Keep
        # only structured fields and the exception class unless a dedicated
        # diagnostic was already supplied by our own error type.
        detail = ": ".join(item for item in (error_code, diagnostic) if item)
        if not detail:
            frame = ""
            try:
                frames = traceback.extract_tb(current.__traceback__)
                if frames:
                    last = frames[-1]
                    frame = f"@{os.path.basename(last.filename)}:{last.lineno}:{last.name}"
            except Exception:
                frame = ""
            detail = f"{type(current).__name__}{frame}"
        if detail:
            parts.append(detail[:240])
        current = current.__cause__ or current.__context__
    return " <- ".join(parts)[:500]


def _context_failure_diagnostic(exc: BaseException) -> str:
    """Return a stable, credential-free reason for context startup failures."""
    text = (str(exc or "") or str(getattr(exc, "message", "") or "")).casefold()
    if _browser_process_lost(exc):
        reason = "browser_process_lost"
    elif any(marker in text for marker in ("proxy", "socks", "connect", "connection", "timed out", "timeout")):
        reason = "proxy_or_transport"
    elif any(marker in text for marker in ("permission", "denied", "executable", "binary")):
        reason = "browser_runtime"
    else:
        reason = "context_api_error"
    return f"exception_type={type(exc).__name__[:80] or 'UnknownError'}; reason={reason}"


def _safe_url(page: Any) -> str:
    try:
        parsed = urlsplit(str(getattr(page, "url", "") or ""))
        if parsed.scheme and parsed.hostname:
            return _safe_event_url(parsed.geturl()) or "页面地址未知"
    except Exception:
        pass
    return "页面地址未知"


async def _body_text(page: Any) -> str:
    try:
        return clean(await page.locator("body").inner_text(timeout=1500), 1800)
    except Exception:
        return ""


# Debug artifacts have a stricter redaction boundary than ordinary business
# diagnostics.  The latter intentionally keeps short numeric identifiers and
# route labels useful; a retained browser page, however, can contain an OTP in
# visible text or a console error.  Keep this policy local to the Camoufox
# scene dump so changing it cannot alter normal task/log semantics.
_DEBUG_OTP_CONTEXT_RE = re.compile(
    r"(?ix)"
    r"(?:\b(?:one[\s_-]?time(?:[\s_-]?password)?|otp|"
    r"verification(?:[\s_-]?code)?|verify(?:[\s_-]?code)?|"
    r"authentication(?:[\s_-]?code)?|auth(?:[\s_-]?code)?|"
    r"security[\s_-]?(?:code|pin|passcode|token)|pass[\s_-]?code|"
    r"pin|code|(?:access|login|email|sms)[\s_-]?code"
    r")\b|验证码|校验码|动态码|一次性密码|認証(?:コード)?|確認コード|検証コード)"
 )
_DEBUG_NUMERIC_OTP_RE = re.compile(r"(?<![A-Za-z0-9])\d{4,7}(?![A-Za-z0-9])")
# Require both letters and digits so ordinary words ("security", "Cloudflare")
# are never treated as an OTP.  A context label is still required before this
# candidate is masked; this avoids destroying browser/version identifiers such
# as ``HTTP403`` in otherwise useful diagnostics.
_DEBUG_ALNUM_OTP_RE = re.compile(
    r"(?<![A-Za-z0-9])(?=[A-Za-z0-9]{4,12}(?![A-Za-z0-9]))"
    r"(?=[A-Za-z0-9]*[A-Za-z])(?=[A-Za-z0-9]*\d)[A-Za-z0-9]{4,12}(?![A-Za-z0-9])"
)
# Verification codes are also commonly rendered as short groups, for example
# ``A1-B2-C3`` or ``12 34 56``.  A contiguous-token pass cannot see those
# values, so inspect bounded groups separately and apply the same conservative
# status/version allow-list below.
_DEBUG_GROUPED_ALNUM_RE = re.compile(
    r"(?<![A-Za-z0-9])[A-Za-z0-9]{1,8}(?:[\s-][A-Za-z0-9]{1,8}){1,7}(?![A-Za-z0-9])"
)
# Grouped-code matching can include the label immediately before the value
# (for example, ``code A1-B2-C3``).  Keep those labels in the scene dump while
# masking only the value itself.
_DEBUG_GROUP_LABELS = {
    "one", "time", "password", "otp", "verification", "verify",
    "authentication", "auth", "security", "code", "pin", "passcode",
    "token", "access", "login", "email", "sms",
}
# A few unambiguous protocol/status spellings are useful diagnostics rather
# than OTPs.  Version-like values need an explicit version/build/release
# label; a bare ``v2024`` is still treated as a possible code.
_DEBUG_ALNUM_STATUS_RE = re.compile(r"(?i)^(?:https?|http|err|ns|tls|ssl)\d{3}$")
_DEBUG_VERSION_CONTEXT_RE = re.compile(r"(?i)\b(?:version|build|release)\b")
_DEBUG_EMAIL_RE = re.compile(r"(?i)(?<![\w.+-])[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}(?![\w.-])")
_DEBUG_PHONE_RE = re.compile(r"(?<![\w])\+?\d{8,15}(?![\w])")
_SENSITIVE_BODY_RE = re.compile(
    r"(?i)[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}|"
    r"(?<![A-Za-z0-9])\+?\d{8,15}(?![A-Za-z0-9])|"
    r"(?<![A-Za-z0-9])\d{4,7}(?![A-Za-z0-9])"
)
_SCREENSHOT_SCAN_LIMIT = 100_000


def _debug_otp_context(text: str, start: int, end: int, *, radius: int = 72) -> bool:
    """Return whether a candidate is near an OTP/verification label."""
    window = text[max(0, start - radius):min(len(text), end + radius)]
    return bool(_DEBUG_OTP_CONTEXT_RE.search(window))


def _debug_alnum_is_safe_identifier(text: str, start: int, end: int, candidate: str) -> bool:
    """Keep protocol/version labels while rejecting code-shaped tokens."""
    if _DEBUG_ALNUM_STATUS_RE.fullmatch(candidate):
        # HTTP/NS/TLS status tokens are diagnostics, never credentials. Keep
        # them readable even when the surrounding message also mentions a
        # verification code.
        return True
    if re.fullmatch(r"(?i)v\d{1,4}", candidate):
        window = text[max(0, start - 32):min(len(text), end + 32)]
        return bool(_DEBUG_VERSION_CONTEXT_RE.search(window))
    return False


def _debug_grouped_is_candidate(text: str, start: int, end: int, candidate: str) -> bool:
    """Recognize grouped code-shaped values without masking normal prose."""
    chunks = [item for item in re.split(r"[\s-]+", candidate) if item]
    compact = "".join(chunks)
    if len(compact) < 4 or not any(char.isdigit() for char in compact):
        return False
    # ``Version v2024`` (and the equivalent build/release labels) is a
    # diagnostic identifier, not an OTP.  The broad context window may also
    # contain a real ``code`` label elsewhere in the same message, so check
    # the version token before applying that context.
    if len(chunks) == 2 and re.fullmatch(r"(?i)v\d{1,4}", chunks[1]):
        window = text[max(0, start - 32):min(len(text), end + 32)]
        if _DEBUG_VERSION_CONTEXT_RE.search(window):
            return False
    if _debug_alnum_is_safe_identifier(text, start, end, compact):
        return False
    # An OTP label makes even uneven groups (``AB-1234``) unambiguous.  In an
    # unlabeled string require several short code-like groups so phrases such
    # as ``Version v2024`` are not swallowed as a single secret.
    if _debug_otp_context(text, start, end):
        return True
    return (
        len(chunks) >= 2
        and all(len(chunk) <= 4 for chunk in chunks)
        and sum(any(char.isdigit() for char in chunk) for chunk in chunks) >= 2
    )


def _debug_grouped_secret_start(text: str, start: int, end: int) -> int:
    """Return the first character of a grouped secret, after its label."""
    candidate = text[start:end]
    tokens = list(re.finditer(r"[A-Za-z0-9]+", candidate))
    secret_start = start
    for token in tokens:
        word = token.group(0).casefold()
        if word not in _DEBUG_GROUP_LABELS:
            break
        secret_start = start + token.end()
    while secret_start < end and text[secret_start] in " \\t-":
        secret_start += 1
    return secret_start


def _sanitize_debug_text(value: Any, limit: int = 800, *, mask_bare_numeric: bool = True) -> str:
    """Redact credentials and likely OTPs before writing a debug artifact.

    Numeric 4--7 digit values are masked even without a nearby label.  This
    is deliberately fail-closed for retained browser scenes because a page
    may render a code by itself (for example, a single ``<p>1234</p>``).  Mixed
    alphanumeric candidates are masked when they have an OTP context or match
    a code-like standalone token.  A small protocol/status allowlist keeps
    values such as ``HTTP403`` readable; version values are retained only
    beside an explicit ``version``/``build``/``release`` label.
    """
    text = sanitize_failure_text(value, max(0, int(limit)))
    if not text:
        return ""
    replacements: list[tuple[int, int, str]] = []
    occupied_until = -1
    for match in _DEBUG_GROUPED_ALNUM_RE.finditer(text):
        if match.start() < occupied_until:
            continue
        if _debug_grouped_is_candidate(text, match.start(), match.end(), match.group(0)):
            secret_start = _debug_grouped_secret_start(text, match.start(), match.end())
            if secret_start < match.end():
                replacements.append((secret_start, match.end(), "<验证码>"))
            occupied_until = match.end()
    for matcher, is_numeric in ((_DEBUG_NUMERIC_OTP_RE, True), (_DEBUG_ALNUM_OTP_RE, False)):
        for match in matcher.finditer(text):
            if match.start() < occupied_until:
                continue
            if is_numeric:
                should_mask = mask_bare_numeric or _debug_otp_context(text, match.start(), match.end())
            else:
                candidate = match.group(0)
                should_mask = _debug_otp_context(text, match.start(), match.end())
                if _debug_alnum_is_safe_identifier(text, match.start(), match.end(), candidate):
                    # Keep unambiguous protocol/version forms readable when
                    # they are not part of an OTP-labelled message.
                    should_mask = False
                elif not should_mask:
                    # Mixed alpha/numeric values are a common OTP format even
                    # when a page renders the value without its label. Keep
                    # ordinary protocol/status identifiers above readable.
                    should_mask = True
            if should_mask:
                replacements.append((match.start(), match.end(), "<验证码>"))
                occupied_until = match.end()
    for start, end, replacement in reversed(replacements):
        text = text[:start] + replacement + text[end:]
    return text[: max(0, int(limit))]


def _debug_body_has_sensitive_token(value: Any) -> bool:
    """Check raw page text before screenshot capture, without returning it."""
    text = str(value or "")
    if _SENSITIVE_BODY_RE.search(text) or _DEBUG_EMAIL_RE.search(text) or _DEBUG_PHONE_RE.search(text):
        return True
    for match in _DEBUG_NUMERIC_OTP_RE.finditer(text):
        # A bare code is unsafe to capture; labels are not required here.
        if _debug_otp_context(text, match.start(), match.end()) or len(match.group(0)) in {4, 5, 6, 7}:
            return True
    for match in _DEBUG_ALNUM_OTP_RE.finditer(text):
        if not _debug_alnum_is_safe_identifier(text, match.start(), match.end(), match.group(0)):
            return True
    for match in _DEBUG_GROUPED_ALNUM_RE.finditer(text):
        if _debug_grouped_is_candidate(text, match.start(), match.end(), match.group(0)):
            return True
    return False


async def _screenshot_safety_check(page: Any) -> tuple[bool, str]:
    """Verify the complete readable body before allowing a screenshot.

    A short diagnostic snapshot is useful for state classification, but it is
    not sufficient to prove that a later part of the page is safe to capture.
    If the body cannot be read in full (or exceeds the bounded scan size), we
    skip the screenshot instead of guessing that masking was complete.
    """
    try:
        value = await page.locator("body").inner_text(timeout=1500)
        body = str(value or "")
    except Exception as exc:
        return False, f"无法读取页面正文（{type(exc).__name__}）"
    if len(body) > _SCREENSHOT_SCAN_LIMIT:
        return False, "页面正文过长，无法可靠脱敏"
    if _debug_body_has_sensitive_token(body):
        return False, "页面正文疑似含敏感值，未保存截图"
    return True, ""


async def _snapshot(page: Any) -> dict[str, Any]:
    body = await _body_text(page)
    try:
        title = clean(await page.title(), 160)
    except Exception:
        title = ""
    return {"url": _safe_url(page), "title": title, "body": body}


def _safe_event_url(value: Any) -> str:
    """Keep only a request host/path for the bounded debug event trace."""
    try:
        parsed = urlsplit(str(value or ""))
        if not parsed.hostname:
            return ""
        host = parsed.hostname
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        path = parsed.path or "/"
        # Decode nested percent-encoding before applying the redaction rules.
        # A bounded loop handles values encoded by browser/router layers while
        # avoiding unbounded work on malformed input.
        for _ in range(8):
            decoded = unquote(path)
            if decoded == path:
                break
            path = decoded
        trusted_host = (
            host.casefold() == "chatgpt.com"
            or host.casefold().endswith(".chatgpt.com")
            or host.casefold() == "openai.com"
            or host.casefold().endswith(".openai.com")
        )
        if not trusted_host:
            path = "/[路径已隐藏]"
        # Opaque authorization/callback routes and encoded values are not
        # useful for diagnosis. Keep known ChatGPT routes readable, but hide
        # tokens, mailbox addresses, phone numbers and long opaque segments.
        path = re.sub(r"(?i)[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", "<邮箱>", path)
        path = re.sub(r"(?<!\d)\+?\d{8,15}(?!\d)", "<手机号>", path)
        # URL query strings are discarded below, but short OTPs can also be
        # embedded in a verification route path.  Apply the debug-only text
        # policy here after decoding nested percent escapes.
        path = _sanitize_debug_text(path, 500)
        path = re.sub(r"(?i)((?:token|code|state|nonce|session|key|secret|credential|assertion))(?:/|=)[^/?#&]+", r"\1/<已隐藏>", path)
        path = re.sub(
            r"(?i)(/(?:authorize|callback|oauth|continue|session))(?:/[^/?#]*)?",
            r"\1/<已隐藏>",
            path,
        )
        # Encoded query strings can become a literal ``?`` only after the
        # repeated decode above.  Drop that suffix even when it does not use a
        # recognized key, because it may contain an opaque authorization value.
        if "?" in path or "#" in path:
            path = re.split(r"[?#]", path, maxsplit=1)[0].rstrip("/") or "/"
            path = f"{path}/<已隐藏>" if path != "/" else "/<已隐藏>"
        elif re.search(r"[&=]", path):
            path = path.split("&", 1)[0].split("=", 1)[0].rstrip("/") or "/"
            path = f"{path}/<已隐藏>" if path != "/" else "/<已隐藏>"
        # Leave no partially encoded token-looking value in the public trace.
        if "%" in path:
            path = "/[路径已隐藏]"
        path = "/".join(
            "<已隐藏>" if len(segment) > 96 and re.fullmatch(r"[A-Za-z0-9._~-]+", segment) else segment
            for segment in path.split("/")
        )
        return f"{parsed.scheme.lower()}://{host}{path}"[:500]
    except Exception:
        return ""


def _safe_incident_id(value: Any) -> str:
    candidate = str(value or "").strip().upper()
    if re.fullmatch(r"LOG-\d{8}-[A-Z0-9]{8}", candidate):
        return candidate
    return ""


def _safe_debug_task_id(value: Any) -> str:
    """Project a task identifier without allowing email/phone-like input.

    Production Free IDs use a stable ``free-*``/``task-*`` namespace.  Keep
    those identifiers useful for correlation, while hashing arbitrary direct
    caller values (which may accidentally be an email, phone, or URL).
    """
    candidate = str(value or "").strip()
    if not candidate:
        return ""
    candidate = candidate[:160]
    internal = re.fullmatch(
        r"(?i)(?:free|task|batch|camoufox)(?:[-_.:][A-Za-z0-9][A-Za-z0-9_.:-]{0,150})?",
        candidate,
    )
    if internal and not re.search(
        r"(?i)(?:@|https?://|socks5?h?://|\+?\d{8,15})", candidate,
    ):
        return candidate
    return f"task-{fingerprint(candidate)}"


def _runtime_bool(value: Any, default: bool = False) -> bool:
    """Parse booleans at low-level compatibility boundaries.

    Production config is normalized before it reaches the pool, but direct
    callers and older integrations can still pass strings such as ``"false"``.
    Python's plain ``bool("false")`` would incorrectly enable the option.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    normalized = str(value or "").strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    return bool(default)


def _effective_camoufox_headless(config: Mapping[str, Any] | None) -> tuple[bool, bool]:
    """Return ``(debug_enabled, effective_headless)`` for a browser config."""
    values = config if isinstance(config, Mapping) else {}
    # Public callers commonly pass the full Free config while low-level pool
    # callers pass the nested ``camoufox`` section.  Normalize both shapes at
    # this boundary so a direct compatibility call cannot silently re-enable
    # the wrong window mode.
    nested = values.get("camoufox")
    if isinstance(nested, Mapping):
        values = nested
    debug_mode = _runtime_bool(values.get("debug_mode"), True)
    persisted_headless = _runtime_bool(values.get("headless"), True)
    return debug_mode, (False if debug_mode else persisted_headless)


def _safe_body_markers(value: Any) -> list[str]:
    """Report only sensitivity classes, never page/response text."""
    text = str(value or "")
    markers: list[str] = []
    if re.search(r"(?i)[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", text):
        markers.append("<邮箱>")
    if re.search(r"(?<!\d)\+?\d{8,15}(?!\d)", text):
        markers.append("<手机号>")
    if _DEBUG_NUMERIC_OTP_RE.search(text) or any(
        _debug_otp_context(text, match.start(), match.end())
        or not _DEBUG_ALNUM_STATUS_RE.fullmatch(match.group(0))
        for match in _DEBUG_ALNUM_OTP_RE.finditer(text)
    ) or any(
        _debug_grouped_is_candidate(text, match.start(), match.end(), match.group(0))
        for match in _DEBUG_GROUPED_ALNUM_RE.finditer(text)
    ):
        markers.append("<验证码>")
    return markers


def _safe_proxy_fingerprint(provided: Any, proxy: Any = "") -> str:
    """Accept only the runtime's fixed-size hexadecimal proxy fingerprint."""
    candidate = str(provided or "").strip().lower()
    if re.fullmatch(r"[0-9a-f]{16}", candidate):
        return candidate
    raw_proxy = str(proxy or "").strip()
    return fingerprint(raw_proxy) if raw_proxy else ""


class _DebugTrace:
    """Small, credential-free page event ring buffer."""

    def __init__(self, limit: int = 100) -> None:
        self.events: Deque[dict[str, Any]] = deque(maxlen=max(10, int(limit)))
        self.lock = threading.Lock()

    def add(self, kind: str, **fields: Any) -> None:
        event: dict[str, Any] = {
            "kind": clean(kind, 40),
            "at": round(time.time(), 3),
        }
        for key, value in fields.items():
            if value in (None, ""):
                continue
            if key in {"url", "safe_page"}:
                value = _safe_event_url(value) or ("" if not value else "页面地址未知")
            elif key in {"status"}:
                try:
                    value = max(0, min(599, int(value)))
                except (TypeError, ValueError):
                    continue
            elif key in {"method", "type", "name", "failure", "message", "text", "error"}:
                value = _sanitize_debug_text(value, 300)
            else:
                value = _sanitize_debug_text(value, 300)
            if value not in (None, ""):
                event[clean(key, 40)] = value
        with self.lock:
            self.events.append(event)

    def snapshot(self) -> list[dict[str, Any]]:
        with self.lock:
            return [dict(item) for item in self.events]


def _page_debug_trace(page: Any) -> _DebugTrace:
    trace = getattr(page, "_gptphone_debug_trace", None)
    if isinstance(trace, _DebugTrace):
        return trace
    trace = _DebugTrace()
    try:
        setattr(page, "_gptphone_debug_trace", trace)
    except Exception:
        pass
    # Playwright event callbacks are synchronous even for async pages. Keep
    # each callback tiny and sanitize before the event can enter the buffer.
    on = getattr(page, "on", None)
    if callable(on):
        try:
            on("console", lambda message: trace.add(
                "console", type=getattr(message, "type", ""),
                text=getattr(message, "text", ""),
            ))
            on("pageerror", lambda error: trace.add(
                "page_error", error=str(error or ""),
            ))
            on("requestfailed", lambda request: trace.add(
                "request_failed", method=getattr(request, "method", ""),
                url=getattr(request, "url", ""),
                failure=(request.failure() if callable(getattr(request, "failure", None)) else ""),
            ))
            on("response", lambda response: trace.add(
                "response", method=(getattr(getattr(response, "request", None), "method", "") or ""),
                url=getattr(response, "url", ""), status=getattr(response, "status", 0),
            ))
            on("framenavigated", lambda frame: trace.add(
                "navigation", url=getattr(frame, "url", ""),
            ))
        except Exception:
            trace.add("trace_setup", message="页面事件监听器安装失败")
    return trace


async def _capture_debug_dom(page: Any) -> dict[str, Any]:
    """Dump a small DOM projection without values, scripts or full URLs."""
    script = """
    () => {
      const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
        && getComputedStyle(el).visibility !== 'hidden'
        && getComputedStyle(el).display !== 'none';
      const allowed = new Set(['a','button','input','textarea','select','option','label','form','main','h1','h2','h3','p']);
      const elements = [];
      for (const el of document.querySelectorAll('body *')) {
        if (elements.length >= 240 || !allowed.has(el.tagName.toLowerCase()) || !visible(el)) continue;
        // Never serialize a control's current value. Textareas can expose
        // their value through innerText/textContent, and select/option nodes
        // may contain an email or one-time code in their visible text.
        const tag = el.tagName.toLowerCase();
        const isValueControl = ['input','textarea','select','option'].includes(tag);
        const text = isValueControl ? '' : String(el.innerText || el.textContent || '').replace(/\\s+/g, ' ').trim().slice(0, 240);
        const href = el.getAttribute('href') || '';
        let safeHref = '';
        try { const parsed = new URL(href, location.href); safeHref = parsed.origin + (parsed.pathname || '/'); } catch (_) {}
        elements.push({
          tag, role: el.getAttribute('role') || '',
          type: el.getAttribute('type') || '',
          aria_label: el.getAttribute('aria-label') || '',
          text, href: safeHref,
        });
      }
      return {title: String(document.title || '').slice(0, 160), url: location.origin + (location.pathname || '/'), elements};
    }
    """
    try:
        evaluation = page.evaluate(script)
        if inspect.isawaitable(evaluation):
            # A detached or stalled page must never prevent the failure
            # cleanup path from closing its context. Playwright's page-level
            # default timeout does not consistently cover evaluate callbacks.
            raw = await asyncio.wait_for(evaluation, timeout=3.0)
        else:
            raw = evaluation
    except Exception as exc:
        return {"error": f"DOM 采集失败（{type(exc).__name__}）", "elements": []}
    if not isinstance(raw, Mapping):
        return {"error": "DOM 采集返回格式无效", "elements": []}
    elements: list[dict[str, Any]] = []
    for item in raw.get("elements", []) if isinstance(raw.get("elements"), list) else []:
        if not isinstance(item, Mapping):
            continue
        row: dict[str, Any] = {"tag": clean(item.get("tag"), 20)}
        for key in ("role", "type", "aria_label", "text"):
            value = _sanitize_debug_text(item.get(key), 240)
            if value:
                row[key] = value
        href = _safe_event_url(item.get("href"))
        if href:
            row["href"] = href
        elements.append(row)
    return {
        "title": _sanitize_debug_text(raw.get("title"), 160),
        "url": _safe_event_url(raw.get("url")),
        "elements": elements,
    }


_ARTIFACT_LOCK = threading.RLock()
_ARTIFACT_PROTECTED_SESSIONS: set[str] = set()
_ARTIFACT_SESSION_RE = re.compile(r"^cam-debug-[0-9a-f]{12}$")


def _atomic_artifact_write(path: Path, payload: Any) -> None:
    """Write one debug artifact atomically inside its target directory."""
    text = json.dumps(payload, ensure_ascii=False, indent=2)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=str(path.parent),
        prefix=f".{path.name}.", suffix=".tmp", delete=False,
    )
    temporary_path = Path(temporary.name)
    try:
        with temporary:
            temporary.write(text)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_path, path)
    finally:
        try:
            temporary_path.unlink()
        except FileNotFoundError:
            pass


def _trim_debug_artifacts(artifact_root: Path, *, current_session: str = "") -> None:
    """Keep at most 50 generated scenes without deleting active sessions."""
    with _ARTIFACT_LOCK:
        protected = set(_ARTIFACT_PROTECTED_SESSIONS)
        if current_session:
            protected.add(current_session)
        try:
            directories = sorted(
                (
                    item for item in artifact_root.iterdir()
                    if item.is_dir() and _ARTIFACT_SESSION_RE.fullmatch(item.name)
                ),
                key=lambda item: item.stat().st_mtime,
            )
            excess = max(0, len(directories) - 50)
            for old in directories:
                if excess <= 0:
                    break
                if old.name in protected:
                    continue
                try:
                    shutil.rmtree(old)
                    excess -= 1
                except OSError:
                    continue
        except (FileNotFoundError, OSError):
            return


async def _capture_debug_artifact(
    *,
    page: Any,
    artifact_root: Path | None,
    session_id: str,
    artifact_id: str,
    summary: Mapping[str, Any],
    trace: _DebugTrace,
) -> dict[str, Any]:
    """Persist bounded debug evidence, degrading safely when an API is absent."""
    result = {"artifact_id": artifact_id, "artifact_path": "", "screenshot": "skipped", "screenshot_reason": ""}
    if artifact_root is None:
        result["screenshot_reason"] = "未配置现场目录"
        return result
    directory = artifact_root / session_id
    try:
        directory.mkdir(parents=True, exist_ok=True)
        dom = await _capture_debug_dom(page)
        _atomic_artifact_write(directory / "dom.json", dom)
        # Keep the on-disk summary a strict projection even if a compatibility
        # caller passes extra fields.  In particular, never let raw kwargs,
        # exception objects or response payloads become an artifact channel.
        payload: dict[str, Any] = {}
        for key in (
            "task_id", "incident_id", "node_code", "node_label", "error_code",
            "page_type", "safe_page", "proxy_fingerprint", "created_at",
        ):
            if key not in summary:
                continue
            value = summary.get(key)
            if key == "created_at":
                try:
                    parsed_time = float(value)
                    if not (0 <= parsed_time <= 4_102_444_800):
                        continue
                    payload[key] = parsed_time
                except (TypeError, ValueError, OverflowError):
                    continue
            elif key in {"incident_id", "proxy_fingerprint"}:
                text = str(value or "").strip()
                if key == "incident_id":
                    text = _safe_incident_id(text)
                else:
                    text = _safe_proxy_fingerprint(text)
                if text:
                    payload[key] = text
            elif key == "task_id":
                text = _safe_debug_task_id(value)
                if text:
                    payload[key] = text
            elif key == "safe_page":
                # ``safe_page`` has already been reduced to an origin/path by
                # ``_safe_event_url``.  Running it through the generic failure
                # sanitizer would redact the entire URL again and discard the
                # useful route needed to identify the failed page.
                text = _safe_event_url(value)
                if text:
                    payload[key] = text
            else:
                text = _sanitize_debug_text(value, 240)
                if text:
                    payload[key] = text
        payload["artifact_id"] = artifact_id
        payload["dom_file"] = "dom.json"
        payload["events"] = trace.snapshot()
        # Mask every user-editable control. If the browser implementation does
        # not support Playwright's mask option, skip instead of risking an
        # unredacted screenshot.
        screenshot = directory / "screenshot.png"
        screenshot_safe, screenshot_reason = await _screenshot_safety_check(page)
        if not screenshot_safe:
            result["screenshot_reason"] = screenshot_reason
        else:
            try:
                controls = [page.locator(selector) for selector in (
                    "input", "textarea", "select", "[contenteditable='true']", "iframe",
                    "[role='textbox']", "[aria-label*='email' i]", "[aria-label*='code' i]",
                    "[aria-label*='otp' i]", "[autocomplete*='email' i]", "[autocomplete*='one-time-code' i]",
                    "[name*='email' i]", "[name*='code' i]", "[name*='otp' i]", "[type='password']",
                )]
                await page.screenshot(path=str(screenshot), mask=controls, mask_color="#000000", timeout=5000)
                result["screenshot"] = "saved"
            except Exception as exc:
                result["screenshot_reason"] = f"截图未保存（{type(exc).__name__}）"
                try:
                    screenshot.unlink()
                except FileNotFoundError:
                    pass
        payload["screenshot"] = result["screenshot"]
        payload["screenshot_reason"] = result["screenshot_reason"]
        _atomic_artifact_write(directory / "summary.json", payload)
        result["artifact_path"] = str(directory)
    except Exception as exc:
        result["screenshot_reason"] = f"现场写入失败（{type(exc).__name__}）"
    # Direct pool callers may intentionally omit an artifact directory.  The
    # live headed context is still useful in that case; artifact retention is
    # simply skipped instead of dereferencing a missing root during cleanup.
    if artifact_root is not None:
        _trim_debug_artifacts(artifact_root, current_session=session_id)
    return result


async def _close_context_safely(context: Any, timeout: float) -> bool:
    """Close a context even when the owning registration task was cancelled."""
    close = getattr(context, "close", None)
    if not callable(close):
        return True
    try:
        result = close()
    except Exception:
        return False
    if not inspect.isawaitable(result):
        return True
    task = asyncio.create_task(result)
    try:
        await asyncio.wait_for(asyncio.shield(task), timeout=max(0.1, float(timeout)))
        return True
    except asyncio.TimeoutError:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        return False
    except asyncio.CancelledError:
        # ``wait_for`` cancellation is expected for registration timeouts. Do
        # not let it skip context cleanup or browser recycling in ``finally``.
        try:
            await asyncio.wait_for(asyncio.shield(task), timeout=max(0.1, float(timeout)))
            return True
        except asyncio.TimeoutError:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            return False
        except asyncio.CancelledError:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        return False
    except Exception:
        await asyncio.gather(task, return_exceptions=True)
        return False


async def _close_async_resource(close_fn: Callable[[], Any], timeout: float) -> bool:
    """Close one async browser resource and always retrieve its task result.

    Playwright's manager close can leave an internal future behind when its
    browser process disappears during a timeout. Running the close coroutine
    in an explicit task and gathering it after cancellation prevents the
    ``Future exception was never retrieved`` warning from leaking into the
    next Camoufox batch.
    """
    try:
        result = close_fn()
    except BaseException:
        return False
    if not inspect.isawaitable(result):
        return True
    task = asyncio.create_task(result)
    budget = max(0.1, float(timeout))
    try:
        await asyncio.wait_for(asyncio.shield(task), timeout=budget)
        return True
    except asyncio.TimeoutError:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        return False
    except asyncio.CancelledError:
        # Defer caller cancellation until this resource has had a bounded
        # chance to settle, then consume the task result before returning.
        try:
            await asyncio.wait_for(asyncio.shield(task), timeout=budget)
        except asyncio.TimeoutError:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        except BaseException:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        return False
    except BaseException:
        await asyncio.gather(task, return_exceptions=True)
        return False


async def _page_visible_text(page: Any) -> str:
    return await _body_text(page)


async def _hard_proxy_block_reason(page: Any) -> str:
    snapshot = await _snapshot(page)
    combined = f"{snapshot['title']} {snapshot['body']}".casefold()
    marker = next((item for item in _PROXY_BLOCK_PAGE_MARKERS if item in combined), "")
    if not marker:
        return ""
    return f"ChatGPT 拒绝当前代理（{marker}）"


async def _is_cloudflare_challenge(page: Any) -> bool:
    snapshot = await _snapshot(page)
    combined = f"{snapshot['title']} {snapshot['body']}".casefold()
    return any(marker in combined for marker in (
        "cloudflare", "just a moment", "verify you are human", "turnstile",
        "checking your browser", "performing security verification", "安全验证",
    ))


async def _wait_challenge_then_stop(page: Any, *, timeout: float = 30.0) -> None:
    """Wait briefly for a challenge to clear, then stop without bypassing it."""
    if not await _is_cloudflare_challenge(page):
        return
    deadline = time.monotonic() + max(0.0, float(timeout))
    while time.monotonic() < deadline:
        await asyncio.sleep(2.0)
        if not await _is_cloudflare_challenge(page):
            return
    raise CamoufoxBrowserError(
        "free_camoufox_challenge", "等待 Camoufox 安全验证",
        "Camoufox 页面安全验证未在等待窗口内完成",
        retryable=False, error_code="free_camoufox_security_challenge",
        safe_page=_safe_url(page), page_type="security",
    )


async def _wait_for_any_selector(page: Any, selectors: tuple[str, ...], *, timeout: float = 30.0) -> str | None:
    deadline = time.monotonic() + max(0.1, float(timeout))
    while time.monotonic() < deadline:
        for selector in selectors:
            try:
                locator = page.locator(selector).first
                if await locator.is_visible(timeout=500):
                    return selector
            except Exception:
                continue
        await asyncio.sleep(0.4)
    return None


async def _find_visible_selector(page: Any, selectors: tuple[str, ...]) -> str | None:
    for selector in selectors:
        try:
            if await page.locator(selector).first.is_visible(timeout=500):
                return selector
        except Exception:
            continue
    return None


async def _fill_input_like_user(
    page: Any,
    selector: str,
    value: str,
    *,
    click: bool = True,
) -> bool:
    try:
        locator = page.locator(selector).first
        await locator.wait_for(state="visible", timeout=8000)
        if click:
            await locator.click()
        await locator.fill("")
        await locator.fill(str(value))
        return True
    except Exception:
        try:
            await page.locator(selector).first.fill(str(value))
            return True
        except Exception:
            return False


async def _submit_email_form_stable(page: Any, email: str) -> dict[str, Any]:
    """Submit only the visible email input's form with React-compatible events."""
    script = r"""
    ({email}) => {
      const value = String(email || '').trim();
      const visible = el => !!el
        && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
        && getComputedStyle(el).visibility !== 'hidden'
        && getComputedStyle(el).display !== 'none'
        && !el.disabled
        && el.getAttribute('aria-disabled') !== 'true';
      const inputSelectors = [
        'input#login-email', 'input[type="email"]', 'input[name="email"]',
        'input[name="username"]', 'input[autocomplete*="email"]',
        'input[autocomplete*="username"]', 'input[inputmode="email"]',
        'input[id*="email" i]'
      ];
      let input = null;
      let inputSelector = '';
      for (const selector of inputSelectors) {
        const candidate = [...document.querySelectorAll(selector)]
          .find(el => visible(el) && !el.readOnly);
        if (candidate) {
          input = candidate;
          inputSelector = selector;
          break;
        }
      }
      if (!input) {
        return {ok: false, reason: 'missing_email_input', form_present: false,
          input_selector: '', submit_selector: ''};
      }
      if (!value || !value.includes('@')) {
        return {ok: false, reason: 'invalid_email_value', form_present: false,
          input_selector: inputSelector, submit_selector: ''};
      }
      const form = input.closest('form');
      if (!form) {
        return {ok: false, reason: 'missing_email_form', form_present: false,
          input_selector: inputSelector, submit_selector: ''};
      }

      const external = /google|apple|microsoft|github|facebook|saml|sso|oauth|social|oidc|idp|provider|authorize|consent|grant|allow/i;
      const cssPath = el => {
        const parts = [];
        let current = el;
        while (current && current.nodeType === 1 && current !== document.body) {
          if (current.id) {
            parts.unshift('#' + (window.CSS?.escape
              ? CSS.escape(current.id) : current.id.replace(/[^a-zA-Z0-9_-]/g, '\\$&')));
            break;
          }
          let part = current.tagName.toLowerCase();
          const parent = current.parentElement;
          if (parent) {
            const siblings = [...parent.children]
              .filter(item => item.tagName === current.tagName);
            if (siblings.length > 1) {
              part += ':nth-of-type(' + (siblings.indexOf(current) + 1) + ')';
            }
          }
          parts.unshift(part);
          current = parent;
        }
        return parts.join(' > ');
      };
      const describe = el => [
        el.id, el.name, el.type, el.getAttribute('data-testid'),
        el.getAttribute('data-provider'), el.getAttribute('aria-label'),
        el.getAttribute('href'), el.textContent || ''
      ].filter(Boolean).join(' ');
      const controls = [...form.querySelectorAll('button,input[type="submit"]')]
        .filter(el => visible(el) && !external.test(describe(el)));
      const submit = controls.find(
        el => (el.getAttribute('type') || '').toLowerCase() === 'submit'
      ) || controls[0] || null;
      if (!submit) {
        return {ok: false, reason: 'missing_safe_submit', form_present: true,
          input_selector: inputSelector, submit_selector: ''};
      }

      const setter = Object.getOwnPropertyDescriptor(
        HTMLInputElement.prototype, 'value'
      )?.set;
      input.scrollIntoView({block: 'center', inline: 'nearest'});
      input.focus();
      if (setter) setter.call(input, value); else input.value = value;
      try {
        input.dispatchEvent(new InputEvent('beforeinput', {
          bubbles: true, cancelable: true, inputType: 'insertText', data: value
        }));
      } catch (_) {}
      try {
        input.dispatchEvent(new InputEvent('input', {
          bubbles: true, inputType: 'insertText', data: value
        }));
      } catch (_) {
        input.dispatchEvent(new Event('input', {bubbles: true}));
      }
      input.dispatchEvent(new Event('change', {bubbles: true}));
      input.dispatchEvent(new FocusEvent('blur', {bubbles: true}));
      input.blur();
      input.focus();

      const submitSelector = cssPath(submit);
      return {ok: true, reason: 'form_prepared_for_enter', form_present: true,
        input_selector: cssPath(input) || inputSelector,
        submit_selector: submitSelector || ''};
    }
    """
    try:
        result = await page.evaluate(script, {"email": str(email or "").strip()})
    except Exception as exc:
        return {
            "ok": False,
            "reason": f"evaluate_{type(exc).__name__}",
            "form_present": False,
            "input_selector": "",
            "submit_selector": "",
        }
    if not isinstance(result, Mapping):
        return {
            "ok": False,
            "reason": "invalid_result",
            "form_present": False,
            "input_selector": "",
            "submit_selector": "",
        }
    return {
        "ok": bool(result.get("ok")),
        "reason": clean(result.get("reason"), 80),
        "form_present": bool(result.get("form_present")),
        "input_selector": clean(result.get("input_selector"), 500),
        "submit_selector": clean(result.get("submit_selector"), 500),
    }


async def _click_first(page: Any, selectors: tuple[str, ...], *, timeout: float = 8.0) -> str | None:
    for selector in selectors:
        try:
            locator = page.locator(selector).first
            await locator.wait_for(state="visible", timeout=max(500, int(timeout * 1000)))
            await locator.click(timeout=5000)
            return selector
        except Exception:
            continue
    return None


async def _click_exact_button_text(
    page: Any, texts: tuple[str, ...], *, timeout: float = 8.0,
) -> str | None:
    """Click a visible button whose complete label matches one of ``texts``.

    Playwright's ``:has-text`` is intentionally substring-based, so using it
    for the Get started recovery can select ``Continue with Google`` instead
    of the standalone email ``Continue`` action.  Exact matching in Python
    keeps the recovery safe across Camoufox/Firefox selector implementations.
    """
    wanted = {" ".join(str(item or "").split()).casefold() for item in texts}
    deadline = time.monotonic() + max(0.5, float(timeout))
    while time.monotonic() < deadline:
        try:
            buttons = page.locator("button")
            count = await buttons.count()
        except Exception:
            count = 0
        for index in range(count):
            try:
                button = buttons.nth(index)
                if not await button.is_visible(timeout=250):
                    continue
                label = " ".join(str(await button.inner_text() or "").split()).casefold()
                if label not in wanted or not await button.is_enabled(timeout=250):
                    continue
                await button.click(timeout=3000)
                return label
            except Exception:
                continue
        await asyncio.sleep(0.25)
    return None


async def _wait_for_submit_enabled(page: Any, selectors: tuple[str, ...], *, timeout: float = 20.0) -> str | None:
    deadline = time.monotonic() + max(0.1, float(timeout))
    while time.monotonic() < deadline:
        for selector in selectors:
            try:
                locator = page.locator(selector).first
                if not await locator.is_visible(timeout=500):
                    continue
                if not await locator.get_attribute("disabled"):
                    return selector
            except Exception:
                continue
        await asyncio.sleep(0.5)
    return None


async def _submit_visible_form(page: Any, selector: str) -> bool | None:
    """Press Enter and report ``None`` when dispatch outcome is uncertain.

    ``False`` is reserved for failures before Playwright was asked to press
    the key.  An exception raised by ``press`` itself can happen after the
    browser dispatched the event, so callers must not treat it as proof that
    submission did not start.
    """
    action_started = False
    try:
        locator = page.locator(selector).first
        action_started = True
        # The state loop observes the resulting page itself.  Waiting for a
        # navigation inside Playwright can raise after Enter was dispatched
        # when the auth shell is slow, so request dispatch-only semantics.
        press = getattr(locator, "press")
        try:
            signature = inspect.signature(press)
        except (TypeError, ValueError):
            signature = None
        if signature is None:
            await press("Enter", no_wait_after=True)
        else:
            try:
                signature.bind("Enter", no_wait_after=True)
            except TypeError:
                # Keep lightweight test doubles and older Playwright builds
                # usable while preferring the non-waiting API when available.
                await press("Enter")
            else:
                await press("Enter", no_wait_after=True)
        return True
    except Exception:
        return None if action_started else False


async def _click_visible_submit(page: Any, selector: str) -> bool | None:
    """Click a previously identified safe submit control.

    The DOM can be replaced between the JS preparation pass and the click, so
    the locator is deliberately created afresh for every call.
    """
    if not selector:
        return False
    action_started = False
    try:
        locator = page.locator(selector).first
        await locator.wait_for(state="visible", timeout=1500)
        if hasattr(locator, "is_enabled") and not await locator.is_enabled(timeout=500):
            return False
        action_started = True
        # The auth shell can take longer than the action timeout to finish its
        # navigation.  Waiting for navigation here turns a successful click
        # into a TimeoutError and incorrectly marks the mailbox as consumed
        # with an ``uncertain`` failure.  The state loop below owns transition
        # waiting, so return as soon as Playwright dispatches the click.
        await locator.click(timeout=3000, no_wait_after=True)
        return True
    except Exception:
        return None if action_started else False


async def _auth_error_text(page: Any) -> str:
    text = await _page_visible_text(page)
    for token in (
        "Incorrect", "invalid", "Invalid", "account_deactivated", "account_suspended",
        "account_banned", "Authentication Error", "already registered", "already signed up",
        "Email is required", "已有账号",
    ):
        if token in text:
            return token
    return ""


async def _accept_about_you_consents(page: Any, log: Callable[[str, str], None]) -> bool:
    try:
        checkboxes = page.locator("input[type='checkbox']")
        count = await checkboxes.count()
    except Exception:
        return False
    for index in range(count):
        try:
            checkbox = checkboxes.nth(index)
            if not await checkbox.is_visible(timeout=300):
                continue
            if not await checkbox.is_checked():
                await checkbox.check(timeout=3000)
            log("Camoufox 资料页已接受必选隐私条款", "info")
            return True
        except Exception:
            continue
    return False


async def _confirm_birthday(page: Any, log: Callable[[str, str], None], *, timeout: float = 1.0) -> bool:
    selectors = (
        "[role='dialog'] button:has-text('OK')",
        "[role='dialog'] button:has-text('Confirm')",
        "button:has-text('OK')",
    )
    deadline = time.monotonic() + max(0.0, float(timeout))
    while time.monotonic() <= deadline:
        for selector in selectors:
            try:
                locator = page.locator(selector).first
                if await locator.is_visible(timeout=250):
                    await locator.click(timeout=3000)
                    log("Camoufox 资料页已确认生日", "info")
                    return True
            except Exception:
                continue
        await asyncio.sleep(0.2)
    return False


async def _goto_with_retry(
    page: Any,
    url: str,
    *,
    timeout_ms: int,
    proxy_retryable: bool,
    attempts: int = 1,
    log: Callable[..., Any] | None = None,
) -> Any:
    """Navigate like aBaiFreeGPT while retaining AutoPhone's safe errors.

    A DOMContentLoaded timeout does not prove that the page is unusable.  The
    reference flow checks the login form before rotating a proxy; this is
    important when several Camoufox contexts are under CPU or network load.
    """
    last_error: BaseException | None = None
    total_attempts = max(1, int(attempts or 1))
    for attempt in range(total_attempts):
        try:
            response = await _goto_with_diagnostics(
                page,
                url,
                timeout_ms=timeout_ms,
                proxy_retryable=proxy_retryable,
                wrap_errors=False,
            )
            await _wait_challenge_then_stop(page)
            return response
        except CamoufoxBrowserError as exc:
            last_error = exc
            if exc.error_code in {"camoufox_navigation_rate_limited", "camoufox_proxy_blocked"}:
                raise
            if getattr(exc, "recycle_required", False):
                raise
            raise
        except Exception as exc:
            last_error = exc
            if _browser_process_lost(exc):
                failure = CamoufoxBrowserError(
                    "free_camoufox_launch", "启动 Camoufox 浏览器池",
                    "Camoufox 浏览器进程已断开", retryable=True,
                    error_code="camoufox_browser_disconnected",
                    diagnostic="category=browser_process_lost; exception_type="
                    f"{type(exc).__name__}", safe_page=_safe_url(page),
                    page_type="unknown",
                )
                _mark_recycle_required(failure, "browser process lost during navigation")
                raise failure from exc

            retryable_navigation = (
                _is_transient_navigation_error(exc)
                or "timeout" in str(exc or "").casefold()
                or type(exc).__name__.casefold() == "error"
            )
            if retryable_navigation:
                hard_block = await _hard_proxy_block_reason(page)
                if hard_block:
                    failure = CamoufoxBrowserError(
                        "free_camoufox_navigation", "打开 Camoufox 注册页面",
                        "Camoufox 页面被代理或上游服务阻断",
                        retryable=bool(proxy_retryable),
                        error_code="camoufox_proxy_blocked",
                        diagnostic=f"category=proxy_blocked; marker={hard_block}",
                        safe_page=_safe_url(page), page_type="navigation",
                    )
                    failure.proxy_retryable = bool(proxy_retryable)
                    raise failure from exc
                email_selector = await _wait_for_any_selector(
                    page, EMAIL_SELECTORS, timeout=2,
                )
                if email_selector:
                    if callable(log):
                        try:
                            log(
                                f"导航等待异常但登录表单已可用: {email_selector}",
                                "warn",
                            )
                        except TypeError:
                            log(f"导航等待异常但登录表单已可用: {email_selector}")
                    return None
                if attempt + 1 < total_attempts:
                    await asyncio.sleep(2)
                    continue

            failure = CamoufoxBrowserError(
                "free_camoufox_navigation", "打开 Camoufox 注册页面",
                "Camoufox 页面导航失败", retryable=bool(proxy_retryable),
                error_code="camoufox_navigation_failed",
                diagnostic=_navigation_diagnostic(exc, page),
                safe_page=_safe_url(page), page_type="navigation",
            )
            failure.proxy_retryable = bool(proxy_retryable)
            raise failure from exc
    raise CamoufoxBrowserError(
        "free_camoufox_navigation", "打开 Camoufox 注册页面",
        "Camoufox 页面导航失败", retryable=bool(proxy_retryable),
        error_code="camoufox_navigation_failed",
        diagnostic=_navigation_diagnostic(last_error, page) if last_error else "category=navigation_error",
        safe_page=_safe_url(page), page_type="navigation",
    ) from last_error


async def _response_retry_after(response: Any) -> int:
    """Read only a numeric Retry-After value; never persist response headers."""
    value: Any = None
    try:
        headers = getattr(response, "headers", None)
        if isinstance(headers, Mapping):
            value = headers.get("retry-after") or headers.get("Retry-After")
    except Exception:
        value = None
    if value is None:
        try:
            value = response.header_value("retry-after")
            if inspect.isawaitable(value):
                value = await value
        except Exception:
            value = None
    try:
        return max(0, min(86400, int(float(str(value or "0").strip()))))
    except (TypeError, ValueError):
        return 0


async def _goto_with_diagnostics(
    page: Any,
    url: str,
    *,
    timeout_ms: int,
    proxy_retryable: bool = False,
    wrap_errors: bool = True,
) -> Any:
    """Navigate while preserving safe HTTP/proxy diagnostics for the manager."""
    try:
        response = await page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
    except FreeRegisterError:
        raise
    except Exception as exc:
        if not wrap_errors:
            raise
        if _browser_process_lost(exc):
            failure = CamoufoxBrowserError(
                "free_camoufox_launch", "启动 Camoufox 浏览器池",
                "Camoufox 浏览器进程已断开",
                retryable=True, error_code="camoufox_browser_disconnected",
                diagnostic="browser process lost", safe_page=_safe_url(page), page_type="unknown",
            )
            _mark_recycle_required(failure, "browser process lost during navigation")
            raise failure from exc
        failure = CamoufoxBrowserError(
            "free_camoufox_navigation", "打开 Camoufox 注册页面",
            "Camoufox 页面导航失败",
            retryable=bool(proxy_retryable), error_code="camoufox_navigation_failed",
            diagnostic=_navigation_diagnostic(exc, page),
            safe_page=_safe_url(page), page_type="navigation",
        )
        failure.proxy_retryable = bool(proxy_retryable)
        raise failure from exc

    try:
        status = int(getattr(response, "status", 0) or 0)
    except (TypeError, ValueError):
        status = 0
    retry_after = await _response_retry_after(response)
    body = (await _body_text(page)).casefold()
    # A Cloudflare/Turnstile document may carry HTTP 403. Classify the
    # security page before the generic proxy-block branch so the manager
    # never rotates or replays the registration around a challenge.
    if await _is_cloudflare_challenge(page):
        raise CamoufoxBrowserError(
            "free_camoufox_challenge", "等待 Camoufox 安全验证",
            "Camoufox 页面返回 Cloudflare/Turnstile 安全验证，已停止自动流程",
            retryable=False, provider_status=status or None,
            provider_code=f"http_{status}" if status else "security_challenge",
            error_code="free_camoufox_security_challenge",
            diagnostic="security challenge page",
            safe_page=_safe_url(page), page_type="security",
        )
    blocked = any(marker in body for marker in _PROXY_BLOCK_PAGE_MARKERS)
    if status == 429:
        raise CamoufoxBrowserError(
            "free_camoufox_navigation", "打开 Camoufox 注册页面",
            "Camoufox 页面返回业务限流（429），不会自动重放注册",
            retryable=False, provider_status=429, provider_code="http_429",
            retry_after_seconds=retry_after, error_code="camoufox_navigation_rate_limited",
            diagnostic=f"provider_status=429; retry_after={retry_after}s",
            safe_page=_safe_url(page), page_type="navigation",
        )
    if blocked or status in {403, 407} or status >= 500:
        code = "camoufox_proxy_blocked" if blocked else f"camoufox_navigation_http_{status}"
        failure = CamoufoxBrowserError(
            "free_camoufox_navigation", "打开 Camoufox 注册页面",
            "Camoufox 页面被代理或上游服务阻断",
            retryable=bool(proxy_retryable), provider_status=status or None,
            provider_code=f"http_{status}" if status else "proxy_blocked",
            error_code=code, diagnostic="proxy blocked page" if blocked else f"provider_status={status}",
            safe_page=_safe_url(page), page_type="navigation",
        )
        failure.proxy_retryable = bool(proxy_retryable)
        raise failure
    return response


async def _new_context(
    browser: Any,
    *,
    proxy: dict[str, Any] | None,
) -> Any:
    """Create a fingerprinted context, with a version-compatible fallback."""
    _, AsyncNewContext = _load_camoufox_api()
    context_kwargs = {
        "viewport": {"width": 1024, "height": 720},
        "locale": "en-US",
        "timezone_id": "America/New_York",
        "reduced_motion": "reduce",
        "service_workers": "block",
    }
    try:
        return await AsyncNewContext(
            browser,
            os=random.choice(("windows", "macos")),
            proxy=proxy,
            **context_kwargs,
        )
    except TypeError as exc:
        # Camoufox has changed its fingerprint/context helper signature across
        # releases. Keep registration usable with the same proxy and locale if
        # that helper rejects a keyword; a plain Playwright context is still
        # isolated and is preferable to losing the mailbox before navigation.
        new_context = getattr(browser, "new_context", None)
        if not callable(new_context):
            raise
        # Some Camoufox/Playwright combinations expose a Browser-like object
        # whose generated `new_context` method accepts only the core options.
        # Retry with progressively smaller option sets while preserving the
        # task proxy. This keeps the fallback useful across both API families.
        fallback_options = (
            context_kwargs,
            {key: value for key, value in context_kwargs.items() if key not in {"service_workers"}},
            {key: value for key, value in context_kwargs.items() if key not in {"service_workers", "reduced_motion"}},
            {key: value for key, value in context_kwargs.items() if key in {"viewport", "locale", "timezone_id"}},
            {"locale": context_kwargs["locale"]},
            {},
        )
        last_error: BaseException = exc
        for options in fallback_options:
            try:
                return await new_context(proxy=proxy, **options)
            except TypeError as fallback_exc:
                last_error = fallback_exc
                continue
            except Exception as fallback_exc:
                raise TypeError(
                    f"fingerprint context rejected TypeError; standard context rejected {type(fallback_exc).__name__}"
                ) from exc
        raise TypeError(
            f"fingerprint context rejected TypeError; standard context rejected {type(last_error).__name__}"
        ) from exc


async def _visible(page: Any, selectors: tuple[str, ...], timeout: int = 500) -> Any | None:
    for selector in selectors:
        try:
            locator = page.locator(selector).first
            if await locator.is_visible(timeout=timeout):
                return locator
        except Exception:
            continue
    return None


async def _fill(locator: Any, value: str) -> bool:
    try:
        await locator.click()
        await locator.fill("")
        await locator.fill(str(value))
        return True
    except Exception:
        try:
            await locator.fill(str(value))
            return True
        except Exception:
            return False


async def _click(page: Any, selectors: tuple[str, ...], timeout: int = 2500) -> bool:
    for selector in selectors:
        try:
            locator = page.locator(selector).first
            if await locator.is_visible(timeout=500):
                if await locator.is_enabled(timeout=500):
                    await locator.click(timeout=timeout)
                    return True
        except Exception:
            continue
    return False


async def _submit(locator: Any) -> bool:
    try:
        await locator.press("Enter")
        return True
    except Exception:
        return False


async def _browser_signin_url(page: Any, email: str) -> str:
    """Use ChatGPT's same-origin signin endpoint when the entry form is late."""
    script = """
    async ({email, deviceId}) => {
      try {
        const csrf = await fetch('https://chatgpt.com/api/auth/csrf', {
          credentials: 'include', headers: {accept: 'application/json'}
        });
        const csrfPayload = await csrf.json();
        const csrfToken = String(csrfPayload?.csrfToken || '');
        if (!csrfToken) return {ok: false, url: ''};
        const query = new URLSearchParams({
          prompt: 'login', 'ext-oai-did': deviceId,
          auth_session_logging_id: crypto.randomUUID(),
          screen_hint: 'login_or_signup', login_hint: email
        });
        const body = new URLSearchParams({
          callbackUrl: 'https://chatgpt.com/', csrfToken, json: 'true'
        });
        const response = await fetch(
          'https://chatgpt.com/api/auth/signin/openai?' + query.toString(),
          {method: 'POST', credentials: 'include', redirect: 'follow',
           headers: {'accept': 'application/json', 'content-type': 'application/x-www-form-urlencoded'},
           body: body.toString()}
        );
        const payload = await response.json().catch(() => ({}));
        return {ok: response.ok, url: String(payload?.url || '')};
      } catch (_) {
        return {ok: false, url: ''};
      }
    }
    """
    try:
        result = await page.evaluate(script, {"email": str(email), "deviceId": str(uuid.uuid4())})
    except Exception:
        return ""
    if not isinstance(result, Mapping) or not result.get("ok"):
        return ""
    candidate = str(result.get("url") or "").strip()
    try:
        parsed = urlsplit(candidate)
    except (TypeError, ValueError):
        return ""
    # The same-origin endpoint must hand back the OpenAI authorization route;
    # never let a malformed or external provider URL enter the browser flow.
    if parsed.scheme.casefold() != "https" or (parsed.hostname or "").casefold() != "auth.openai.com":
        return ""
    return candidate


async def _page_state(page: Any) -> str:
    raw_url = str(getattr(page, "url", "") or "")
    parsed = urlsplit(raw_url)
    host = (parsed.hostname or "").casefold()
    path = (parsed.path or "/").casefold().rstrip("/") or "/"
    body = (await _body_text(page)).casefold()
    # The registration flow must never enter a third-party OAuth provider.
    # Keep this explicit so a broad text selector cannot silently turn an
    # entry-shell recovery into a Google login and wait for it as "unknown".
    if host.endswith("accounts.google.com") or host.endswith("appleid.apple.com"):
        return "external_auth"
    if any(marker in body for marker in ("cloudflare", "verify you are human", "turnstile", "just a moment", "安全验证")):
        return "security"
    if host == "chatgpt.com" and path in {"", "/"}:
        return "home"
    if host == "chatgpt.com" and ("/auth/login" in path or "/login" in path):
        if await _visible(page, PASSWORD_SELECTORS, 250):
            return "login_password"
        if await _visible(page, OTP_SELECTORS, 250):
            return "otp"
        return "entry"
    if "auth.openai.com" in host:
        if any(marker in path for marker in ("/about-you", "/about_you", "/birthdate", "/profile")):
            return "profile"
        if path in {"/log-in/password", "/login/password"}:
            return "login_password"
        if "password" in path or "new-password" in path:
            return "signup_password"
        if any(marker in path for marker in ("email-verification", "email-otp", "/verify")):
            if await _visible(page, PASSWORD_SELECTORS, 250):
                return "signup_password"
            return "otp" if await _visible(page, OTP_SELECTORS, 250) else "email_verification"
        if any(marker in path for marker in ("/authorize", "/callback", "/continue")):
            return "oauth_callback"
        # The auth host can briefly render an email entry shell at /log-in
        # after the same-origin signin fallback. Match the reference flow's
        # selector fallback so it is not classified as an unknown state.
        if await _visible(page, EMAIL_SELECTORS, 250):
            return "entry"
    if await _visible(page, PASSWORD_SELECTORS, 250):
        return "signup_password"
    if await _visible(page, OTP_SELECTORS, 250):
        return "otp"
    if await _visible(page, NAME_SELECTORS, 250) or await _visible(page, BIRTHDAY_SELECTORS, 250):
        return "profile"
    return "unknown"


async def _wait_state(page: Any, timeout: float, *states: str) -> str:
    deadline = time.monotonic() + max(1.0, float(timeout))
    wanted = set(states)
    current = "unknown"
    while time.monotonic() < deadline:
        current = await _page_state(page)
        if current in wanted:
            return current
        await asyncio.sleep(0.35)
    return current


async def _accept_consents(page: Any) -> None:
    try:
        checkboxes = page.locator("input[type='checkbox']")
        count = await checkboxes.count()
    except Exception:
        return
    for index in range(count):
        try:
            item = checkboxes.nth(index)
            if await item.is_visible(timeout=250) and not await item.is_checked():
                await item.check(timeout=2500)
        except Exception:
            continue


async def _sync_hidden_birthday_input(page: Any, birthdate: str) -> bool:
    """Mirror the reference fallback for date controls rendered off-screen."""
    for selector in BIRTHDAY_SELECTORS:
        try:
            locator = page.locator(selector).first
            if await locator.is_visible(timeout=500):
                await locator.click()
                await locator.fill(birthdate)
                return True
        except Exception:
            continue
    for selector in BIRTHDAY_SELECTORS:
        try:
            updated = await page.evaluate(
                """(sel, value) => {
                    const el = document.querySelector(sel);
                    if (!el) return false;
                    el.value = value;
                    el.dispatchEvent(new Event('input', {bubbles: true}));
                    el.dispatchEvent(new Event('change', {bubbles: true}));
                    return true;
                }""",
                selector,
                birthdate,
            )
            if updated:
                return True
        except Exception:
            continue
    return False


def _reference_age_and_birthdate() -> tuple[int, str]:
    """Use the reference flow's adult age range with a matching birthday."""
    age = random.SystemRandom().randint(18, 35)
    today = date.today()
    return age, f"{today.year - age:04d}-{today.month:02d}-{today.day:02d}"


async def _complete_profile(page: Any, log: Callable[[str, str], None]) -> None:
    name = await _visible(page, NAME_SELECTORS)
    if name:
        await _fill(name, random_display_name())
    age = await _visible(page, AGE_SELECTORS)
    if age:
        await _fill(age, "25")
    birthday = await _visible(page, BIRTHDAY_SELECTORS)
    if birthday:
        await _fill(birthday, random_birthdate())
    await _accept_consents(page)
    if not await _click(page, PROFILE_SUBMIT_SELECTORS, timeout=5000):
        if name:
            await _submit(name)
    log("Camoufox 资料页已提交", "info")


async def _submit_existing_login_password(page: Any, password: str) -> bool:
    """Fill and submit a password for an already-existing Free account.

    Existing-account authentication must use the account's saved password;
    the fixed registration password is intentionally never accepted here.
    Resolve the live locator on every call because auth.openai.com can replace
    the form while React hydrates or after a failed click.
    """
    value = str(password or "")
    if not value:
        return False
    selector = await _wait_for_any_selector(page, LOGIN_PASSWORD_SELECTORS, timeout=15)
    if not selector or not await _fill_input_like_user(page, selector, value):
        return False
    if await _click_first(page, LOGIN_PASSWORD_SUBMIT_SELECTORS, timeout=6):
        return True
    # A submit button can disappear while the password input remains attached;
    # use the freshly resolved input as the final, same-form fallback.
    fresh_selector = await _find_visible_selector(page, LOGIN_PASSWORD_SELECTORS)
    return bool(fresh_selector and await _submit_visible_form(page, fresh_selector))


def _stop_requested(value: Any) -> bool:
    """Read a task stop signal without assuming Event versus callable shape."""
    if value is None:
        return False
    try:
        checker = getattr(value, "is_set", None)
        if callable(checker):
            return bool(checker())
        return bool(value()) if callable(value) else bool(value)
    except Exception:
        # A broken stop callback should not keep a blocking OTP worker alive.
        return True


def _invoke_otp_callback(
    callback: Callable[..., Any],
    stage_code: str,
    *,
    stop_requested: Callable[[], bool],
    deadline_monotonic: float,
    deadline_controller: Any = None,
) -> Any:
    """Invoke old and new OTP callback signatures without replaying side effects."""
    try:
        signature = inspect.signature(callback)
    except (TypeError, ValueError):
        try:
            signature = inspect.signature(getattr(callback, "__call__"))
        except (AttributeError, TypeError, ValueError):
            # Do not trial-call an opaque adapter more than once: an internal
            # TypeError is not evidence that a second signature is safe.
            return callback(stage_code)
    candidates = (
        ((stage_code,), {"stop_requested": stop_requested, "deadline_monotonic": deadline_monotonic, "deadline_controller": deadline_controller}),
        ((stage_code,), {"stop_requested": stop_requested, "deadline_monotonic": deadline_monotonic}),
        ((stage_code,), {"stop_requested": stop_requested}),
        ((stage_code,), {"deadline_monotonic": deadline_monotonic}),
        ((stage_code,), {}),
        ((), {"stop_requested": stop_requested, "deadline_monotonic": deadline_monotonic, "deadline_controller": deadline_controller}),
        ((), {"stop_requested": stop_requested, "deadline_monotonic": deadline_monotonic}),
        ((), {"stop_requested": stop_requested}),
        ((), {"deadline_monotonic": deadline_monotonic}),
        ((), {}),
    )
    for args, kwargs in candidates:
        try:
            signature.bind(*args, **kwargs)
        except TypeError:
            continue
        return callback(*args, **kwargs)
    raise TypeError("unsupported OTP callback signature")


def _invoke_mailbox_lease_callback(
    callback: Callable[..., Any],
    *,
    task_id: str,
    email: str,
    driver: str = "camoufox",
    stage: str = "free_camoufox_signup_email",
    submission_definitely_not_started: bool | None = None,
) -> Any:
    """Invoke a mailbox lease hook once across legacy callback signatures."""
    try:
        signature = inspect.signature(callback)
    except (TypeError, ValueError):
        keyword_context: dict[str, Any] = {
            "task_id": task_id,
            "email": email,
            "driver": driver,
            "stage": stage,
        }
        if submission_definitely_not_started is not None:
            keyword_context["submission_definitely_not_started"] = bool(
                submission_definitely_not_started
            )
        return callback(**keyword_context)
    keyword_context = {
        "task_id": task_id,
        "email": email,
        "driver": driver,
        "stage": stage,
    }
    if submission_definitely_not_started is not None:
        keyword_context["submission_definitely_not_started"] = bool(
            submission_definitely_not_started
        )
    candidates = (
        ((), keyword_context),
        ((task_id,), {}),
        ((), {}),
    )
    for args, kwargs in candidates:
        try:
            signature.bind(*args, **kwargs)
        except TypeError:
            continue
        return callback(*args, **kwargs)
    raise TypeError("unsupported mailbox lease callback signature")


async def _await_otp_callback(
    callback: Callable[..., Any],
    stage_code: str,
    *,
    deadline_monotonic: float,
    stop_requested: Any = None,
    deadline_controller: Any = None,
) -> Any:
    """Run a blocking mailbox callback with a hard deadline and cancellation.

    ``asyncio.to_thread`` uses the event loop's executor. Cancelling its await
    does not stop the worker, so a mailbox poll can keep the loop alive long
    after a Camoufox registration deadline. A dedicated daemon worker lets us
    signal cooperative providers and keeps an uncooperative legacy callback
    from blocking browser-pool shutdown.
    """
    loop = asyncio.get_running_loop()
    result: asyncio.Future[Any] = loop.create_future()
    worker_stop = threading.Event()
    end_lock = threading.Lock()
    otp_wait_ended = False
    pending_async_task: asyncio.Task[Any] | None = None
    pending_raw_awaitable: Any = None
    awaitable_lock = threading.Lock()
    abandoned = False

    _deadline_controller_call(deadline_controller, "begin_otp_wait")

    def end_otp_wait_once() -> None:
        nonlocal otp_wait_ended
        with end_lock:
            if otp_wait_ended:
                return
            otp_wait_ended = True
        _deadline_controller_call(deadline_controller, "end_otp_wait")

    def requested() -> bool:
        return worker_stop.is_set() or _stop_requested(stop_requested)

    def consume_exception(future: asyncio.Future[Any]) -> None:
        if not future.cancelled():
            try:
                future.exception()
            except BaseException:
                pass

    def discard_awaitable(value: Any) -> None:
        """Close/cancel an async callback result that the caller abandoned."""
        if not inspect.isawaitable(value):
            return
        close = getattr(value, "close", None)
        if callable(close):
            try:
                close()
                return
            except Exception:
                pass
        cancel = getattr(value, "cancel", None)
        if callable(cancel):
            try:
                cancel()
            except Exception:
                pass

    result.add_done_callback(consume_exception)

    def publish(kind: str, value: Any) -> None:
        if abandoned or result.done():
            if kind == "result":
                discard_awaitable(value)
            return
        if kind == "error":
            result.set_exception(value)
        else:
            result.set_result(value)
        end_otp_wait_once()

    async def resolve_awaitable(value: Any) -> Any:
        current = value
        for _ in range(16):
            if not inspect.isawaitable(current):
                return current
            current = await current
        discard_awaitable(current)
        raise TypeError("OTP callback returned too many nested awaitables")

    def finish_async_task(task: asyncio.Task[Any], original: Any) -> None:
        nonlocal pending_async_task
        if pending_async_task is task:
            pending_async_task = None
        if task.cancelled():
            discard_awaitable(original)
            if not abandoned:
                publish("error", asyncio.CancelledError())
            return
        try:
            value = task.result()
        except BaseException as exc:
            publish("error", exc)
        else:
            publish("result", value)

    def take_raw_awaitable() -> Any:
        nonlocal pending_raw_awaitable
        with awaitable_lock:
            value = pending_raw_awaitable
            pending_raw_awaitable = None
        return value

    def start_awaitable() -> None:
        nonlocal pending_async_task
        value = take_raw_awaitable()
        if value is None:
            return
        if abandoned or result.done():
            discard_awaitable(value)
            return
        resolver = resolve_awaitable(value)
        try:
            task = loop.create_task(resolver)
        except BaseException as exc:
            discard_awaitable(resolver)
            discard_awaitable(value)
            publish("error", exc)
            return
        pending_async_task = task
        task.add_done_callback(
            lambda completed, original=value: finish_async_task(completed, original)
        )

    def worker() -> None:
        nonlocal pending_raw_awaitable
        try:
            value = _invoke_otp_callback(
                callback,
                stage_code,
                stop_requested=requested,
                deadline_monotonic=deadline_monotonic,
                deadline_controller=deadline_controller,
            )
        except BaseException as exc:
            kind, value = "error", exc
        else:
            if inspect.isawaitable(value):
                with awaitable_lock:
                    pending_raw_awaitable = value
                try:
                    loop.call_soon_threadsafe(start_awaitable)
                except RuntimeError:
                    # The owning loop may be closing after cancellation. Close
                    # the coroutine here so it cannot be garbage-collected as
                    # an un-awaited result.
                    discard_awaitable(take_raw_awaitable())
                return
            kind = "result"
        try:
            loop.call_soon_threadsafe(publish, kind, value)
        except RuntimeError:
            # The owning loop may be closing after cancellation. The worker is
            # daemonized and has no useful result to deliver at that point.
            pass

    thread = threading.Thread(
        target=worker,
        name=f"camoufox-otp-{clean(stage_code, 32) or 'wait'}",
        daemon=True,
    )
    thread.start()

    async def await_cleanup(value: Any, timeout: float) -> None:
        """Drain a shielded child while tolerating repeated outer cancels."""
        if not isinstance(value, asyncio.Future):
            try:
                value = asyncio.ensure_future(value)
            except BaseException:
                return
        end = loop.time() + max(0.0, float(timeout))
        while not value.done():
            remaining = end - loop.time()
            if remaining <= 0:
                return
            try:
                await asyncio.wait_for(asyncio.shield(value), timeout=remaining)
            except asyncio.TimeoutError:
                return
            except asyncio.CancelledError:
                current = asyncio.current_task()
                uncancel = getattr(current, "uncancel", None)
                if callable(uncancel):
                    try:
                        while int(getattr(current, "cancelling", lambda: 0)() or 0) > 0:
                            uncancel()
                    except Exception:
                        pass
                continue
            except BaseException:
                return

    async def stop_and_drain() -> None:
        nonlocal abandoned
        if abandoned:
            end_otp_wait_once()
            return
        abandoned = True
        worker_stop.set()
        discard_awaitable(take_raw_awaitable())
        async_task = pending_async_task
        if async_task is not None and not async_task.done():
            async_task.cancel()
        if async_task is not None:
            await await_cleanup(async_task, 0.5)
            if not async_task.done():
                # Allow one deferred-cancellation cleanup pass, but keep the
                # browser pool bounded when a legacy callback never exits.
                async_task.cancel()
                await await_cleanup(async_task, 0.25)
        if result.done():
            try:
                discard_awaitable(result.result())
            except BaseException:
                pass
            end_otp_wait_once()
            return
        # Cooperative mailbox providers normally wake within one poll chunk;
        # retain only a short grace period so browser cleanup remains bounded.
        await await_cleanup(result, 1.5)
        if result.done():
            try:
                discard_awaitable(result.result())
            except BaseException:
                pass
        end_otp_wait_once()

    handoff_started: float | None = None
    try:
        while True:
        # A result that was published at the deadline still belongs to this
        # OTP attempt. Consume it before consulting the active-budget clock;
        # otherwise a zero remaining budget can mask a valid manual submit.
            if _stop_requested(stop_requested):
                await stop_and_drain()
                raise FreeRegisterError(
                    "free_run_stop",
                    "停止 Free 注册",
                    "任务已请求停止，邮箱验证码轮询已中断",
                    retryable=False,
                    error_code="free_run_stop",
                )
            if result.done():
                if _stop_requested(stop_requested):
                    await stop_and_drain()
                    raise FreeRegisterError(
                        "free_run_stop",
                        "停止 Free 注册",
                        "任务已请求停止，邮箱验证码轮询已中断",
                        retryable=False,
                        error_code="free_run_stop",
                    )
                end_otp_wait_once()
                value = await asyncio.shield(result)
                if _stop_requested(stop_requested):
                    await stop_and_drain()
                    raise FreeRegisterError(
                        "free_run_stop",
                        "停止 Free 注册",
                        "任务已请求停止，邮箱验证码轮询已中断",
                        retryable=False,
                        error_code="free_run_stop",
                    )
                return value
            controller = deadline_controller
            prompt_active = _deadline_controller_bool(controller, "manual_prompt_active")
            handoff_active = _deadline_controller_bool(controller, "manual_handoff_active")
            post_submit_grace = _deadline_controller_bool(controller, "manual_submission_grace_active")
            paused = _deadline_controller_bool(controller, "is_paused")
            expired_value = _deadline_controller_call(controller, "is_expired")
            if expired_value is _DEADLINE_CONTROLLER_MISSING:
                try:
                    expired = deadline_monotonic <= time.monotonic()
                except (TypeError, ValueError, OverflowError):
                    expired = False
            else:
                try:
                    expired = bool(expired_value)
                except Exception:
                    try:
                        expired = deadline_monotonic <= time.monotonic()
                    except (TypeError, ValueError, OverflowError):
                        expired = False
            if expired and not paused:
                    # Give the provider a short scheduling handoff to open its
                    # broker prompt. A cooperative provider will mark the
                    # prompt active; an uncooperative callback is cancelled
                    # once this bounded grace elapses.
                    requested_handoff = _deadline_controller_call(
                        controller, "request_manual_handoff"
                    )
                    if requested_handoff is not _DEADLINE_CONTROLLER_MISSING:
                        paused = True
                        handoff_active = True
                        handoff_started = handoff_started or time.monotonic()
            if paused and not prompt_active and not handoff_active:
                handoff_started = handoff_started or time.monotonic()
                handoff_active = (
                    time.monotonic() - handoff_started
                    < MANUAL_OTP_HANDOFF_GRACE_SECONDS
                )
            elif handoff_active and handoff_started is None:
                # A pool watchdog may have opened the handoff before this
                # helper got scheduled. Preserve the original two-second
                # bound instead of starting a fresh grace window.
                handoff_remaining = _deadline_controller_call(
                    controller, "manual_handoff_remaining"
                )
                try:
                    handoff_remaining = float(handoff_remaining)
                    if not math.isfinite(handoff_remaining):
                        raise ValueError
                except (TypeError, ValueError, OverflowError):
                    handoff_remaining = MANUAL_OTP_HANDOFF_GRACE_SECONDS
                handoff_started = time.monotonic() - max(
                    0.0,
                    MANUAL_OTP_HANDOFF_GRACE_SECONDS - handoff_remaining,
                )
            remaining_value = _deadline_controller_call(controller, "remaining")
            if remaining_value is _DEADLINE_CONTROLLER_MISSING:
                try:
                    remaining = deadline_monotonic - time.monotonic()
                except (TypeError, ValueError, OverflowError):
                    remaining = 0.0
            else:
                try:
                    remaining = float(remaining_value)
                    if not math.isfinite(remaining):
                        raise ValueError
                except (TypeError, ValueError, OverflowError):
                    try:
                        remaining = deadline_monotonic - time.monotonic()
                    except (TypeError, ValueError, OverflowError):
                        remaining = 0.0
            if prompt_active or handoff_active or post_submit_grace:
                # The active registration budget is suspended while the
                # operator prompt (or its short handoff) is in flight.
                remaining = max(0.25, remaining)
            if remaining <= 0:
                if (prompt_active or handoff_active or post_submit_grace) and not (
                    handoff_started is not None
                    and not prompt_active
                    and not post_submit_grace
                    and time.monotonic() - handoff_started >= MANUAL_OTP_HANDOFF_GRACE_SECONDS
                ):
                    try:
                        return await asyncio.wait_for(
                            asyncio.shield(result), timeout=0.25,
                        )
                    except asyncio.TimeoutError:
                        continue
                if paused:
                    _deadline_controller_call(controller, "resume_manual", "timeout")
                await stop_and_drain()
                raise CamoufoxBrowserError(
                    "free_email_otp_wait",
                    "等待 Camoufox 邮箱验证码",
                    "邮箱验证码等待已达到注册截止时间",
                    retryable=True,
                    error_code="camoufox_otp_wait_timeout",
                )
            try:
                value = await asyncio.wait_for(
                    asyncio.shield(result),
                    timeout=min(0.25, remaining),
                )
                if _stop_requested(stop_requested):
                    await stop_and_drain()
                    raise FreeRegisterError(
                        "free_run_stop",
                        "停止 Free 注册",
                        "任务已请求停止，邮箱验证码轮询已中断",
                        retryable=False,
                        error_code="free_run_stop",
                    )
                return value
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                await stop_and_drain()
                raise
    except asyncio.CancelledError:
        await stop_and_drain()
        raise
    except BaseException:
        await stop_and_drain()
        raise
    finally:
        end_otp_wait_once()


async def _browser_flow(
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
    timing_fn: TimingCallback | None = None,
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

    def current_deadline() -> float:
        value = _deadline_controller_call(controller, "deadline")
        if value is not _DEADLINE_CONTROLLER_MISSING:
            try:
                candidate = float(value)
                if math.isfinite(candidate):
                    return candidate
            except (TypeError, ValueError, OverflowError):
                pass
        return fallback_deadline

    def budget_remaining() -> float:
        value = _deadline_controller_call(controller, "remaining")
        if value is not _DEADLINE_CONTROLLER_MISSING:
            try:
                candidate = float(value)
                if math.isfinite(candidate):
                    return max(0.0, candidate)
            except (TypeError, ValueError, OverflowError):
                pass
        return max(0.0, current_deadline() - time.monotonic())

    def budget_paused() -> bool:
        return _deadline_controller_bool(controller, "is_paused")

    def budget_grace_active() -> bool:
        return _deadline_controller_bool(controller, "manual_submission_grace_active")

    def budget_grace_remaining() -> float:
        value = _deadline_controller_call(controller, "manual_submission_grace_remaining")
        if value is not _DEADLINE_CONTROLLER_MISSING:
            try:
                candidate = float(value)
                if math.isfinite(candidate):
                    return max(0.0, candidate)
            except (TypeError, ValueError, OverflowError):
                pass
        return MANUAL_OTP_POST_SUBMIT_GRACE_SECONDS if budget_grace_active() else 0.0

    def budget_expired() -> bool:
        value = _deadline_controller_call(controller, "is_expired")
        if value is not _DEADLINE_CONTROLLER_MISSING:
            if bool(value):
                return not budget_grace_active()
            return False
        return not budget_paused() and budget_remaining() <= 0

    deadline = current_deadline()
    account_flow = "existing_login" if force_existing_login else "signup"
    # The manager passes the configured value for normal runs, but resolving
    # it here also keeps direct browser-flow callers aligned with Free config.
    password = str(password or configured_free_password(config))
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
    email_verification_started_at = 0.0
    email_verification_retried = False
    profile_submitted = False
    profile_submitted_at = 0.0
    # ``profile_submitted_at`` guards the reference flow's 60s retry window;
    # the timing anchors below describe two non-overlapping intervals:
    # request completion (leaving profile) and subsequent home confirmation.
    profile_async_started_at = 0.0
    profile_home_state_started_at = 0.0
    profile_home_state_recorded = False
    profile_transition_recorded = False
    entry_transition_deadline = 0.0
    entry_transition_started = 0.0
    entry_transition_recorded = False
    entry_retry_used = False
    entry_signin_fallback_used = False
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

    # A 2FA retry is unambiguously an existing-account login. Reject it before
    # navigation so a missing saved credential cannot consume an OTP or leave a
    # headed debug window open for an impossible flow.
    if force_existing_login and not str(existing_password or "").strip():
        raise CamoufoxBrowserError(
            "free_existing_login", "已有 Free 账号登录",
            "已有账号登录缺少已保存密码，拒绝使用固定注册密码",
            retryable=False, error_code="free_existing_login_password_missing",
        )

    def timing_mark(stage_code: str, code: str, started: float, outcome: str = "success") -> None:
        emit_timing(
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
                _invoke_mailbox_lease_callback,
                mailbox_lease_callback,
                task_id=str(config.get("task_id") or ""),
                email=email,
                driver="camoufox",
                stage="free_camoufox_signup_email",
            )
        except FreeRegisterError:
            raise
        except Exception as exc:
            raise CamoufoxBrowserError(
                "free_mailbox_lease",
                "确认 Free 邮箱租约",
                "提交邮箱前确认租约失败",
                retryable=True,
                error_code="free_mailbox_lease_confirm_failed",
                diagnostic=f"callback={type(exc).__name__}",
                safe_page=_safe_url(page),
                page_type="entry",
            ) from exc
        if outcome is False:
            raise CamoufoxBrowserError(
                "free_mailbox_lease",
                "确认 Free 邮箱租约",
                "提交邮箱前邮箱租约已失效或被其他任务占用",
                retryable=True,
                error_code="free_mailbox_lease_conflict",
                safe_page=_safe_url(page),
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
                _invoke_mailbox_lease_callback,
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
        raise CamoufoxBrowserError(
            stage_code, "准备 Free 邮箱验证码", "邮箱 provider 准备阶段失败",
            error_code=f"{stage_code}_prepare_failed", diagnostic="unsupported_signature",
        )

    async def mark_otp_sent(stage_code: str) -> None:
        if callable(otp_mark_sent):
            await asyncio.to_thread(otp_mark_sent, stage_code)

    def record_profile_timing(state: str, *, terminal_outcome: str = "") -> None:
        """Close profile timing intervals only after an observable outcome.

        ``unknown`` is deliberately left open because auth.openai.com can
        render a transient shell during navigation.  The caller closes it
        explicitly when the state machine raises or reaches its deadline.
        """
        nonlocal profile_transition_recorded
        nonlocal profile_home_state_started_at, profile_home_state_recorded
        if not profile_submitted:
            return
        normalized_state = str(state or "").strip().lower()
        if not profile_transition_recorded:
            if normalized_state == "profile" or normalized_state == "unknown":
                return
            started = profile_async_started_at or profile_submitted_at
            if not started:
                return
            outcome = str(terminal_outcome or _profile_transition_timing_outcome(normalized_state))
            timing_mark("free_camoufox_profile", "profile_async_submit_wait", started, outcome)
            profile_transition_recorded = True
            # Only an accepted auth transition opens the home-confirmation
            # interval.  Security/unexpected outcomes are terminal for this
            # branch and must not manufacture a zero-length home success.
            if outcome != "success":
                profile_home_state_started_at = 0.0
                profile_home_state_recorded = True
                return
            # Start the second interval exactly when the first one ends.
            profile_home_state_started_at = time.monotonic()
            if normalized_state == "home":
                timing_mark(
                    "free_camoufox_profile", "profile_home_state_wait",
                    profile_home_state_started_at, "success",
                )
                profile_home_state_recorded = True
            return
        if profile_home_state_recorded or not profile_home_state_started_at:
            return
        if normalized_state == "home":
            timing_mark(
                "free_camoufox_profile", "profile_home_state_wait",
                profile_home_state_started_at, "success",
            )
            profile_home_state_recorded = True
        elif normalized_state == "security":
            timing_mark(
                "free_camoufox_profile", "profile_home_state_wait",
                profile_home_state_started_at, "security_challenge",
            )
            profile_home_state_recorded = True
        elif terminal_outcome:
            timing_mark(
                "free_camoufox_profile", "profile_home_state_wait",
                profile_home_state_started_at, terminal_outcome,
            )
            profile_home_state_recorded = True

    def close_profile_timing(outcome: str = "timeout") -> None:
        """Close any pending profile intervals before a terminal failure."""
        nonlocal profile_transition_recorded
        nonlocal profile_home_state_started_at, profile_home_state_recorded
        if not profile_submitted:
            return
        if not profile_transition_recorded:
            started = profile_async_started_at or profile_submitted_at
            if started:
                timing_mark("free_camoufox_profile", "profile_async_submit_wait", started, outcome)
                profile_transition_recorded = True
        if profile_home_state_started_at and not profile_home_state_recorded:
            timing_mark(
                "free_camoufox_profile", "profile_home_state_wait",
                profile_home_state_started_at, outcome,
            )
            profile_home_state_recorded = True

    async def submit_entry_email(selector: str, *, recovery: bool = False) -> dict[str, Any]:
        nonlocal entry_form_present, entry_submit_selector, entry_recovery
        nonlocal mailbox_confirmation_abortable
        result = await _submit_email_form_stable(page, email)
        entry_form_present = bool(result.get("form_present"))
        prepared_input_selector = str(result.get("input_selector") or selector).strip()
        entry_submit_selector = clean(
            result.get("submit_selector"), 500,
        )
        if result.get("ok"):
            await confirm_mailbox_before_submit()
            try:
                clicked = await _click_visible_submit(page, entry_submit_selector)
            except BaseException:
                # The click helper may have dispatched an event before its
                # failure surfaced, so this path is intentionally irreversible.
                mailbox_confirmation_abortable = False
                raise
            if clicked is None:
                # ``None`` means the click call was entered but its outcome is
                # unknown. Do not fall back to Enter or revoke the lease.
                mailbox_confirmation_abortable = False
                raise CamoufoxBrowserError(
                    "free_camoufox_signup_email", "填写 Camoufox 注册邮箱",
                    "邮箱提交动作结果不确定，已停止自动回退",
                    error_code="camoufox_email_submit_uncertain",
                    diagnostic=json.dumps({
                        "phase": "entry", "reason": "click_outcome_unknown",
                        "form_present": entry_form_present,
                        "submit_selector": clean(entry_submit_selector, 120),
                    }, ensure_ascii=False),
                    safe_page=_safe_url(page), page_type="entry",
                )
            if clicked:
                mailbox_confirmation_abortable = False
            fallback_input_selector = prepared_input_selector
            if not clicked:
                # The submit control can go stale while React hydrates the
                # form. Re-scan the live DOM before falling back to Enter;
                # using the selector returned by the preparation pass can
                # otherwise target a detached input or the wrong form.
                fresh_selector = await _wait_for_any_selector(
                    page, EMAIL_SELECTORS, timeout=2,
                )
                if fresh_selector:
                    fallback_input_selector = fresh_selector
                    # Re-apply the value when a new input node replaced the
                    # one used by the preparation script. This also restores
                    # the framework input state before pressing Enter.
                    await _fill_input_like_user(page, fallback_input_selector, email)
            if not clicked:
                try:
                    entered = await _submit_visible_form(page, fallback_input_selector)
                except BaseException:
                    mailbox_confirmation_abortable = False
                    raise
                if entered is None:
                    mailbox_confirmation_abortable = False
                    raise CamoufoxBrowserError(
                        "free_camoufox_signup_email", "填写 Camoufox 注册邮箱",
                        "邮箱回车提交动作结果不确定，已停止自动回退",
                        error_code="camoufox_email_submit_uncertain",
                        diagnostic=json.dumps({
                            "phase": "entry", "reason": "enter_outcome_unknown",
                            "form_present": entry_form_present,
                            "input_selector": clean(fallback_input_selector, 120),
                        }, ensure_ascii=False),
                        safe_page=_safe_url(page), page_type="entry",
                    )
                if not entered:
                    await abort_mailbox_confirmation_before_submit()
                    raise CamoufoxBrowserError(
                        "free_camoufox_signup_email", "填写 Camoufox 注册邮箱",
                        "邮箱表单未能提交", error_code="camoufox_email_submit_failed",
                        diagnostic=json.dumps({
                            "phase": "entry",
                            "reason": "prepared_but_enter_failed",
                            "form_present": entry_form_present,
                            "input_selector": clean(fallback_input_selector, 120),
                        }, ensure_ascii=False),
                        safe_page=_safe_url(page), page_type="entry",
                    )
                mailbox_confirmation_abortable = False
            if not clicked:
                entry_submit_selector = clean(fallback_input_selector, 120)
            entry_recovery = "form_resubmit" if recovery else entry_recovery
            log(
                "Camoufox 邮箱表单已提交"
                f"（mode={clean(result.get('reason'), 80)}，"
                f"selector={entry_submit_selector or '-'}）",
                "warn" if recovery else "info",
            )
            return result

        # Re-locate before the fallback path as the initial selector may have
        # become detached while the page hydrated.
        fresh_selector = await _wait_for_any_selector(page, EMAIL_SELECTORS, timeout=2)
        selector = fresh_selector or selector
        if not await _fill_input_like_user(page, selector, email):
            raise CamoufoxBrowserError(
                "free_camoufox_signup_email", "填写 Camoufox 注册邮箱",
                "邮箱输入框写入失败", error_code="camoufox_email_fill_failed",
            )
        await confirm_mailbox_before_submit()
        try:
            entered = await _submit_visible_form(page, selector)
        except BaseException:
            mailbox_confirmation_abortable = False
            raise
        if entered is None:
            mailbox_confirmation_abortable = False
            raise CamoufoxBrowserError(
                "free_camoufox_signup_email", "填写 Camoufox 注册邮箱",
                "邮箱回车提交动作结果不确定，已停止自动回退",
                error_code="camoufox_email_submit_uncertain",
                diagnostic=json.dumps({
                    "phase": "entry", "reason": "enter_outcome_unknown",
                    "form_present": entry_form_present,
                    "input_selector": clean(selector, 120),
                }, ensure_ascii=False),
                safe_page=_safe_url(page), page_type="entry",
            )
        if not entered:
            await abort_mailbox_confirmation_before_submit()
            raise CamoufoxBrowserError(
                "free_camoufox_signup_email", "填写 Camoufox 注册邮箱",
                "邮箱表单未能提交", error_code="camoufox_email_submit_failed",
                diagnostic=json.dumps({
                    "phase": "entry",
                    "reason": clean(result.get("reason"), 80),
                    "form_present": entry_form_present,
                    "input_selector": clean(selector, 120),
                }, ensure_ascii=False),
                safe_page=_safe_url(page), page_type="entry",
            )
        mailbox_confirmation_abortable = False
        entry_submit_selector = clean(selector, 120)
        entry_recovery = "form_resubmit" if recovery else entry_recovery
        fallback = {
            "ok": True,
            "reason": "input_enter_submit",
            "form_present": entry_form_present,
            "input_selector": clean(selector, 120),
            "submit_selector": entry_submit_selector,
        }
        log(
            "Camoufox 邮箱表单已使用 Enter 提交"
            f"（selector={entry_submit_selector or '-'}）",
            "warn" if recovery else "info",
        )
        return fallback

    async def entry_diagnostic(state: str) -> str:
        snapshot = await _snapshot(page)
        return json.dumps({
            "phase": "entry",
            "submitted": bool(entry_submitted),
            "recovery": entry_recovery,
            "safe_page": snapshot.get("url"),
            "page_type": state,
            "form_present": bool(entry_form_present),
            "submit_selector": clean(entry_submit_selector, 120),
            "title": sanitize_failure_text(snapshot.get("title"), 160),
            "sensitive_markers": _safe_body_markers(snapshot.get("body")),
        }, ensure_ascii=False)[:500]

    async def wait_for_state(*states: str, seconds: float = 45.0) -> str:
        grace_remaining = budget_grace_remaining()
        remaining = (
            max(1.0, float(seconds))
            if budget_paused()
            else max(1.0, budget_remaining(), grace_remaining)
        )
        return await _wait_state(page, min(float(seconds), remaining), *states)

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
            current = await _page_state(page)
            if current not in {"otp", "otp_wait"}:
                timing_mark(timing_stage, "otp_input_ready", started, "state_changed")
                return "", current
            selector = await _find_visible_selector(page, OTP_SELECTORS)
            if selector:
                timing_mark(timing_stage, "otp_input_ready", started, "success")
                return selector, current
            await asyncio.sleep(0.5)
        timing_mark(timing_stage, "otp_input_ready", started, "timeout")
        return "", await _page_state(page)

    async def finish_home() -> dict[str, Any]:
        if callable(timing_fn):
            session = await browser_session(
                page,
                timing_fn=timing_fn,
                timing_stage="free_access_token",
            )
        else:
            session = await browser_session(page)
        set_stage("free_access_token")
        token = str(session.get("accessToken") or "")
        if callable(timing_fn):
            plan = await browser_plan_details(
                page,
                token,
                timing_fn=timing_fn,
                timing_stage="free_access_token",
            )
        else:
            plan = await browser_plan_details(page, token)
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
        elif account_flow == "signup" and _runtime_bool(config.get("auto_set_password"), False):
            try:
                password_result = await browser_add_password(
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
                    deadline_monotonic=current_deadline(),
                    deadline_controller=controller,
                    stop_requested=config.get("_stop_requested"),
                    timing_fn=timing_fn,
                )
                result.update(password_result)
                token = str(password_result.get("access_token") or token)
                password_set_after_registration = bool(
                    password_result.get("password_set_after_registration")
                )
            except FreeRegisterError as exc:
                if exc.error_code == "free_run_stop" or exc.node_code == "free_run_stop":
                    raise
                detail = clean(str(exc), 300)
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
        if _runtime_bool(config.get("auto_set_2fa"), True):
            set_stage("free_twofa_enroll")
            try:
                twofa_result = await browser_twofa(
                    page,
                    token,
                    email,
                    otp_callback=otp_callback,
                    otp_prepare=otp_prepare,
                    otp_mark_sent=otp_mark_sent,
                    stage_fn=lambda code: set_stage(code),
                    task_id=str(config.get("task_id") or ""),
                    device_id=str(config.get("device_id") or ""),
                    deadline_monotonic=current_deadline(),
                    deadline_controller=controller,
                    stop_requested=config.get("_stop_requested"),
                    timing_fn=timing_fn,
                )
                if isinstance(twofa_result, Mapping):
                    result.update(twofa_result)
                    token = str(twofa_result.get("access_token") or token)
                else:  # pragma: no cover - compatibility with old adapters
                    result.update({"totp_secret": str(twofa_result or "")})
                set_stage("free_twofa_activate")
                result["twofa_status"] = "enabled"
            except FreeRegisterError as exc:
                if exc.error_code == "free_run_stop" or exc.node_code == "free_run_stop":
                    raise
                result.update({
                    "twofa_status": "pending",
                    "twofa_error": clean(str(exc), 300),
                    "twofa_failure": {
                        "node_code": exc.node_code, "node_label": exc.node_label,
                        "error_code": exc.error_code,
                        "public_message": f"{exc.node_label} [{exc.node_label}/{exc.node_code}]：{clean(str(exc), 300)}",
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
        return finalize_registration_result(
            result,
            driver="camoufox",
            email=email,
            password_used=password_used or bool(result.get("password_set_after_registration")),
        )

    async def finish_password_retry() -> dict[str, Any]:
        """Run only the post-registration password continuation.

        A password retry has an account Token already. It must not open the
        signup entry, submit the mailbox address, or invoke the 2FA helper.
        ``browser_add_password`` owns the independent OTP baseline and the
        Auth/ChatGPT callback sequence.
        """
        token = str(password_retry_token or "").strip()
        if not token:
            raise CamoufoxBrowserError(
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
                raise CamoufoxBrowserError(
                    "free_password_reauth_authorize", "打开密码设置授权页面",
                    f"密码设置前 ChatGPT 页面跳转失败（{type(exc).__name__}）",
                    retryable=True, error_code="free_password_retry_navigation_failed",
                    safe_page=_safe_url(page), page_type="password_retry",
                ) from exc
        set_stage("free_password_eligibility")
        try:
            result = await browser_add_password(
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
                deadline_monotonic=current_deadline(),
                deadline_controller=controller,
                stop_requested=config.get("_stop_requested"),
                timing_fn=timing_fn,
            )
        except FreeRegisterError as exc:
            if exc.error_code == "free_run_stop" or exc.node_code == "free_run_stop":
                raise
            detail = clean(str(exc), 300)
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
        return finalize_registration_result(
            output,
            driver="camoufox",
            email=email,
            password_used=bool(output.get("password_set_after_registration")),
        )

    async def open_registration_entry() -> None:
        """Keep the reference startup gate around only entry navigation."""
        nonlocal entry_submitted, entry_transition_deadline, entry_transition_started
        nonlocal entry_retry_used, entry_signin_fallback_used, entry_recovery
        # Establish the mailbox baseline before the first request that may
        # send an OTP. The provider itself remains AutoPhone's strategy mode.
        if force_existing_login:
            # Capture the pre-login mailbox baseline without announcing an OTP
            # stage before the page has actually requested authentication.
            await prepare_otp("free_existing_login_otp", notify_stage=False)
        navigation_started = time.monotonic()
        try:
            await _goto_with_retry(
                page, CHATGPT_LOGIN_URL, timeout_ms=min(timeout * 1000, 90_000),
                proxy_retryable=not force_existing_login, log=log,
            )
        except Exception:
            emit_timing(
                timing_fn, "free_camoufox_signup", "camoufox_initial_navigation",
                (time.monotonic() - navigation_started) * 1000, "error",
            )
            raise
        emit_timing(
            timing_fn, "free_camoufox_signup", "camoufox_initial_navigation",
            (time.monotonic() - navigation_started) * 1000, "success",
        )
        await asyncio.sleep(1.5)
        form_wait_started = time.monotonic()
        email_selector = await _wait_for_any_selector(page, EMAIL_SELECTORS, timeout=12)
        emit_timing(
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
            entry_transition_deadline = time.monotonic() + 45.0
            entry_transition_started = time.monotonic()
            return

        # Keep the same-origin NextAuth fallback from the reference flow for a
        # delayed shell, but never invent an external provider URL.
        if not force_existing_login:
            await prepare_otp(entry_otp_stage, notify_stage=False)
        authorize_url = await _browser_signin_url(page, email)
        if authorize_url:
            entry_recovery = "same_origin_signin"
            entry_retry_used = True
            entry_signin_fallback_used = True
            await _goto_with_retry(
                page, authorize_url, timeout_ms=min(timeout * 1000, 90_000),
                proxy_retryable=False, log=log,
            )
            entry_submitted = True
            entry_transition_deadline = time.monotonic() + 45.0
            entry_transition_started = time.monotonic()
            return
        snapshot = await _snapshot(page)
        raise CamoufoxBrowserError(
            "free_camoufox_navigation", "打开 Camoufox 注册页面",
            "登录页未找到邮箱输入框，当前代理返回了不可用页面",
            retryable=True, error_code="camoufox_entry_form_missing",
            diagnostic=json.dumps({
                "safe_page": snapshot.get("url"),
                "title": sanitize_failure_text(snapshot.get("title"), 160),
                "page_type": "entry",
            }, ensure_ascii=False)[:500],
            safe_page=snapshot.get("url"), page_type="entry",
        )

    if password_retry:
        return await finish_password_retry()

    if startup_gate is None:
        await open_registration_entry()
    else:
        async with startup_gate:
            await open_registration_entry()

    while not budget_expired():
        step_count += 1
        if _stop_requested(config.get("_stop_requested")):
            raise FreeRegisterError(
                "free_run_stop",
                "停止 Free 注册",
                "任务已请求停止，Camoufox 注册已中断",
                retryable=False,
                error_code="free_run_stop",
            )
        # The about-you endpoint can legitimately take close to a minute to
        # finish. Keep a bounded guard, but do not turn that reference-flow
        # wait into an early page-state failure.
        if step_count > max(120, timeout + 30):
            raise CamoufoxBrowserError(
                "free_camoufox_page_state", "等待 Camoufox 页面状态",
                "注册状态机超出最大推进步数", error_code="camoufox_page_state_limit",
                safe_page=_safe_url(page), page_type="state_machine",
            )
        state = await _page_state(page)
        if (
            entry_submitted
            and entry_transition_started
            and not entry_transition_recorded
            and state not in {"entry", "unknown"}
        ):
            emit_timing(
                timing_fn,
                "free_camoufox_signup_email",
                "camoufox_entry_transition_wait",
                (time.monotonic() - entry_transition_started) * 1000,
                "success",
            )
            entry_transition_recorded = True
        auth_states = {
            "otp", "otp_wait", "email_verification", "signup_password",
            "login_password", "profile", "oauth_callback", "home", "security",
        }
        if state in auth_states:
            auth_phase_locked = True
        elif state == "entry" and auth_phase_locked:
            raise CamoufoxBrowserError(
                "free_camoufox_navigation", "推进 Camoufox 注册页面",
                "邮箱验证已开始后页面返回邮箱入口，拒绝重复提交",
                retryable=False,
                error_code="camoufox_entry_returned_after_otp",
                diagnostic=await entry_diagnostic(state),
                safe_page=_safe_url(page), page_type="entry",
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
            and seen[state] > 4
        ):
            now = time.monotonic()
            # React navigation can briefly expose an unclassified shell after
            # the submit click. Keep polling both ``entry`` and ``unknown``
            # until the same bounded transition window; otherwise five fast
            # DOM polls (about two seconds) can misclassify an asynchronous
            # navigation as a stuck registration.
            if state in {"entry", "unknown"} and entry_submitted and now < entry_transition_deadline:
                await asyncio.sleep(1.0)
                continue
            if state == "entry" and entry_submitted and not entry_retry_used and not auth_phase_locked:
                entry_retry_used = True
                entry_recovery = "form_resubmit"
                await prepare_otp(entry_otp_stage, notify_stage=False)
                reopened = await _click_exact_button_text(
                    page, ("Continue", "继续"), timeout=3,
                )
                if reopened:
                    log("Camoufox 登录壳回退，已重新打开邮箱表单", "warn")
                selector = await _wait_for_any_selector(page, EMAIL_SELECTORS, timeout=8)
                if selector:
                    await submit_entry_email(selector, recovery=True)
                    entry_transition_deadline = time.monotonic() + 45.0
                    entry_transition_started = time.monotonic()
                    seen.clear()
                    await asyncio.sleep(1.0)
                    continue
                log("Camoufox 登录壳未重新显示邮箱表单，准备同源 signin 兜底", "warn")
            if state == "entry" and entry_submitted and not entry_signin_fallback_used and not auth_phase_locked:
                entry_signin_fallback_used = True
                entry_recovery = "same_origin_signin"
                await prepare_otp(entry_otp_stage, notify_stage=False)
                authorize_url = await _browser_signin_url(page, email)
                if not authorize_url:
                    raise CamoufoxBrowserError(
                        "free_camoufox_navigation", "打开 Camoufox 注册页面",
                        "邮箱已提交，但同源 signin 兜底未返回授权地址",
                        retryable=False,
                        error_code="camoufox_entry_signin_fallback_failed",
                        diagnostic=await entry_diagnostic(state),
                        safe_page=_safe_url(page), page_type=state,
                    )
                log("Camoufox 登录壳未推进，开始一次同源 signin 兜底", "warn")
                await _goto_with_retry(
                    page, authorize_url, timeout_ms=min(timeout * 1000, 90_000),
                    proxy_retryable=False, log=log,
                )
                entry_transition_deadline = time.monotonic() + 45.0
                seen.clear()
                await asyncio.sleep(1.0)
                continue
            error_text = await _auth_error_text(page)
            close_profile_timing("unexpected_state")
            raise CamoufoxBrowserError(
                "free_camoufox_navigation", "打开 Camoufox 注册页面",
                error_text or (
                    "邮箱已提交，但 Camoufox 登录入口在限定时间内未跳转"
                    if state == "entry" and entry_submitted
                    else "注册页面状态长时间未推进"
                ),
                retryable=not entry_submitted,
                error_code="camoufox_entry_transition_timeout" if state == "entry" and entry_submitted else "camoufox_page_state_stuck",
                diagnostic=await entry_diagnostic(state),
                safe_page=_safe_url(page), page_type=state,
            )
        if state == "security":
            await _wait_challenge_then_stop(page, timeout=30)
        if state == "home":
            return await finish_home()

        if state == "entry":
            if not entry_submitted:
                selector = await _wait_for_any_selector(page, EMAIL_SELECTORS, timeout=8)
                if selector:
                    set_stage("free_camoufox_signup_email")
                    await prepare_otp(entry_otp_stage, notify_stage=False)
                    await submit_entry_email(selector)
                    entry_submitted = True
                    entry_transition_deadline = time.monotonic() + 45.0
                    entry_transition_started = time.monotonic()
                else:
                    reopened = await _click_exact_button_text(
                        page, ("Continue", "继续"), timeout=3,
                    )
                    if reopened:
                        log("Camoufox 登录壳已重新打开邮箱表单", "warn")
            await asyncio.sleep(1.0)
            continue

        if state == "login_password":
            if not bool(config.get("existing_account_login", True)):
                raise CamoufoxBrowserError(
                    "free_existing_login", "已有 Free 账号登录",
                    "邮箱已存在账号，Camoufox 未开启已有账号邮箱验证码登录",
                    retryable=False, error_code="free_existing_login_disabled",
                )
            account_flow = "existing_login"
            saved_password = str(existing_password or "").strip()
            if not saved_password:
                raise CamoufoxBrowserError(
                    "free_existing_login", "已有 Free 账号登录",
                    "已有账号登录缺少已保存密码，拒绝使用固定注册密码",
                    retryable=False, error_code="free_existing_login_password_missing",
                    safe_page=_safe_url(page), page_type="login_password",
                )
            set_stage("free_existing_login_password")
            now = time.monotonic()
            if not login_password_submitted:
                if not await _submit_existing_login_password(page, saved_password):
                    raise CamoufoxBrowserError(
                        "free_existing_login", "已有 Free 账号登录",
                        "登录密码页输入或提交失败", retryable=False,
                        error_code="free_camoufox_login_password_page",
                        safe_page=_safe_url(page), page_type="login_password",
                    )
                login_password_submitted = True
                login_password_submitted_at = time.monotonic()
            else:
                elapsed = now - (login_password_submitted_at or now)
                if elapsed >= 45:
                    raise CamoufoxBrowserError(
                        "free_existing_login", "已有 Free 账号登录",
                        "登录密码提交后页面未继续", retryable=False,
                        error_code="free_camoufox_login_password_transition_timeout",
                        safe_page=_safe_url(page), page_type="login_password",
                    )
                if elapsed >= 12 and not login_password_submit_retried:
                    await _submit_existing_login_password(page, saved_password)
                    login_password_submit_retried = True
                    log("已有账号登录密码页未跳转，已使用同一密码重试提交", "warn")
            await asyncio.sleep(1.0)
            continue

        if state == "email_verification":
            now = time.monotonic()
            if email_verification_started_at <= 0:
                email_verification_started_at = now
                if await _click_first(page, EMAIL_SUBMIT_SELECTORS, timeout=3):
                    log("邮箱验证页已点击继续", "info")
            elapsed = now - email_verification_started_at
            if elapsed >= 60:
                raise CamoufoxBrowserError(
                    "free_email_otp_validate", "验证 Free 邮箱验证码",
                    "邮箱验证页 60 秒未跳转", error_code="camoufox_email_verification_timeout",
                    safe_page=_safe_url(page), page_type="email_verification",
                )
            if elapsed >= 12 and not email_verification_retried:
                if await _click_first(page, EMAIL_SUBMIT_SELECTORS, timeout=3):
                    log("邮箱验证页未跳转，已重试点击继续", "warn")
                email_verification_retried = True
            await asyncio.sleep(2.0)
            continue

        if state == "signup_password":
            set_stage("free_camoufox_signup_password")
            now = time.monotonic()
            if password_stage_started_at <= 0:
                password_stage_started_at = now
            if now - password_stage_started_at >= 60:
                raise CamoufoxBrowserError(
                    "free_camoufox_signup_password", "提交 Camoufox 注册密码",
                    "注册密码页 60 秒未完成", error_code="camoufox_password_stage_timeout",
                    safe_page=_safe_url(page), page_type="signup_password",
                )
            if password_used:
                elapsed = now - (password_submitted_at or now)
                if elapsed >= 45:
                    raise CamoufoxBrowserError(
                        "free_camoufox_signup_password", "提交 Camoufox 注册密码",
                        "注册密码提交后页面未继续", error_code="camoufox_password_transition_timeout",
                        safe_page=_safe_url(page), page_type="signup_password",
                    )
                if elapsed >= 12 and not password_submit_retried:
                    clicked = await _click_first(page, PASSWORD_SUBMIT_SELECTORS, timeout=3)
                    if not clicked:
                        selector = await _find_visible_selector(page, PASSWORD_SELECTORS)
                        if selector:
                            await _submit_visible_form(page, selector)
                    password_submit_retried = True
                    log("注册密码页未跳转，已使用同一密码重试提交", "warn")
                await asyncio.sleep(2.0)
                continue
            selector = await _wait_for_any_selector(page, PASSWORD_SELECTORS, timeout=15)
            if not selector or not await _fill_input_like_user(page, selector, password):
                raise CamoufoxBrowserError(
                    "free_camoufox_signup_password", "提交 Camoufox 注册密码", "注册密码输入失败",
                    error_code="camoufox_password_fill_failed",
                )
            if not await _click_first(page, PASSWORD_SUBMIT_SELECTORS, timeout=6):
                await _submit_visible_form(page, selector)
            password_used = True
            password_submitted_at = time.monotonic()
            await asyncio.sleep(2.0)
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
                    raise CamoufoxBrowserError(
                        "free_email_otp_validate", "验证 Free 邮箱验证码", "验证码输入框长时间未出现",
                        error_code="camoufox_otp_input_missing",
                    )
                if entry_submitted or account_flow == "existing_login":
                    await mark_otp_sent(stage_code)
                code = str(await _await_otp_callback(
                    otp_callback,
                    stage_code,
                    deadline_monotonic=current_deadline(),
                    deadline_controller=controller,
                    stop_requested=config.get("_stop_requested"),
                ) or "").strip()
                if not code:
                    raise CamoufoxBrowserError(
                        "free_email_otp_wait", "等待 Free 邮箱验证码", "未获取到邮箱验证码",
                        error_code="camoufox_otp_missing",
                    )
                current_state = await _page_state(page)
                if current_state not in {"otp", "otp_wait"}:
                    seen.clear()
                    continue
                otp_submit_started = time.monotonic()
                if not await _fill_input_like_user(page, selector, code):
                    timing_mark(stage_code, "otp_code_submit", otp_submit_started, "error")
                    current_state = await _page_state(page)
                    if current_state not in {"otp", "otp_wait"}:
                        seen.clear()
                        continue
                    raise CamoufoxBrowserError(
                        "free_email_otp_validate", "验证 Free 邮箱验证码", "验证码输入框不可用",
                        error_code="camoufox_otp_input_missing",
                    )
                otp_input_selector = selector
                if not await _click_first(page, PASSWORD_SUBMIT_SELECTORS, timeout=6):
                    await _submit_visible_form(page, selector)
                timing_mark(stage_code, "otp_code_submit", otp_submit_started, "success")
                otp_submitted = True
                otp_submitted_at = time.monotonic()
                otp_submitted_stage = stage_code
                otp_transition_recorded = False
                await asyncio.sleep(1.0)
                continue
            elapsed = time.monotonic() - otp_submitted_at
            if elapsed >= 60:
                if otp_resend_used:
                    raise CamoufoxBrowserError(
                        "free_email_otp_validate", "验证 Free 邮箱验证码",
                        "验证码提交后页面未继续", error_code="camoufox_otp_transition_timeout",
                    )
                await prepare_otp(stage_code)
                if not await _click_first(page, RESEND_SELECTORS, timeout=5):
                    snapshot = await _snapshot(page)
                    raise CamoufoxBrowserError(
                        "free_email_otp_validate", "验证 Free 邮箱验证码",
                        "验证码提交后页面未继续，未找到受控重发入口",
                        error_code="camoufox_otp_resend_unavailable",
                        diagnostic=json.dumps(
                            {
                                "safe_page": snapshot.get("url"),
                                "page_type": await _page_state(page),
                                "title": sanitize_failure_text(snapshot.get("title"), 160),
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
            await asyncio.sleep(1.0)
            continue

        if state == "profile":
            set_stage("free_camoufox_profile")
            if not profile_submitted:
                age_value, birthdate = _reference_age_and_birthdate()
                name_started = time.monotonic()
                name = await _find_visible_selector(page, NAME_SELECTORS)
                name_filled = False
                if name:
                    name_filled = await _fill_input_like_user(page, name, random_display_name())
                timing_mark(
                    "free_camoufox_profile", "profile_name_fill", name_started,
                    "success" if name_filled else "skipped",
                )
                age_started = time.monotonic()
                age = await _find_visible_selector(page, AGE_SELECTORS)
                age_filled = False
                if age:
                    # The about-you age control is visible but can be covered by
                    # the page's transition layer. Filling it directly avoids
                    # Playwright's 30s default click timeout; other fields keep
                    # the existing click-first behavior.
                    age_filled = await _fill_input_like_user(
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
                                await _fill_input_like_user(page, birthday_selector, birthdate)
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
                    hidden_birthday_filled = await _sync_hidden_birthday_input(page, birthdate)
                    hidden_outcome = "success" if hidden_birthday_filled else "skipped"
                else:
                    hidden_outcome = "skipped"
                timing_mark(
                    "free_camoufox_profile", "profile_birthday_hidden_sync", hidden_birthday_started,
                    hidden_outcome,
                )
                consent_started = time.monotonic()
                consent_accepted = await _accept_about_you_consents(page, log)
                timing_mark(
                    "free_camoufox_profile", "profile_consent", consent_started,
                    "success" if consent_accepted else "skipped",
                )
                submit_wait_started = time.monotonic()
                submit_selector = await _wait_for_submit_enabled(page, PROFILE_SUBMIT_SELECTORS, timeout=25)
                timing_mark(
                    "free_camoufox_profile", "profile_submit_button_wait", submit_wait_started,
                    "success" if submit_selector else "error",
                )
                if not submit_selector:
                    raise CamoufoxBrowserError(
                        "free_camoufox_profile", "填写 Camoufox 账号资料",
                        "资料页提交按钮长时间不可用", error_code="camoufox_profile_submit_unavailable",
                    )
                submit_click_started = time.monotonic()
                clicked = await _click_first(page, (submit_selector,), timeout=8)
                timing_mark(
                    "free_camoufox_profile", "profile_submit_click", submit_click_started,
                    "success" if clicked else "not_confirmed",
                )
                profile_submitted = True
                profile_submitted_at = time.monotonic()
                # Start the diagnostic async interval after the optional
                # birthday confirmation.  This keeps the modal's own timing
                # out of the network/page-transition measurement.
                profile_transition_recorded = False
                birthday_modal_started = time.monotonic()
                birthday_confirmed = await _confirm_birthday(page, log, timeout=5)
                timing_mark(
                    "free_camoufox_profile", "profile_birthday_modal", birthday_modal_started,
                    "success" if birthday_confirmed else "skipped",
                )
                profile_async_started_at = time.monotonic()
                profile_home_state_started_at = 0.0
                profile_home_state_recorded = False
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
                    profile_transition_recorded = True
                    profile_submitted = False
                    profile_submitted_at = 0.0
                    profile_async_started_at = 0.0
                    profile_home_state_started_at = 0.0
                    profile_home_state_recorded = False
                    log("Camoufox 资料页提交后 60 秒未跳转，允许重新填写重试", "warn")
                else:
                    await _confirm_birthday(page, log, timeout=0.5)
                    await asyncio.sleep(1.0)
                    continue
            await asyncio.sleep(1.0)
            continue

        if state == "oauth_callback":
            await asyncio.sleep(1.0)
            continue

        if state == "external_auth":
            close_profile_timing("unexpected_state")
            snapshot = await _snapshot(page)
            raise CamoufoxBrowserError(
                "free_camoufox_navigation", "打开 Camoufox 注册页面",
                "注册入口误进入外部 OAuth 登录页；已停止自动操作",
                retryable=False, error_code="camoufox_unexpected_external_auth",
                diagnostic=json.dumps({
                    "safe_page": snapshot.get("url"),
                    "title": sanitize_failure_text(snapshot.get("title"), 160),
                    "page_type": "external_auth",
                }, ensure_ascii=False)[:500],
                safe_page=snapshot.get("url"), page_type="external_auth",
            )

        if state == "security":
            snapshot = await _snapshot(page)
            raise CamoufoxBrowserError(
                "free_camoufox_challenge", "等待 Camoufox 安全验证",
                "注册流程进入安全验证，已停止自动操作", retryable=False,
                error_code="free_camoufox_security_challenge",
                diagnostic=json.dumps({
                    "safe_page": snapshot.get("url"),
                    "page_type": "security",
                    "sensitive_markers": _safe_body_markers(snapshot.get("body")),
                }, ensure_ascii=False)[:500],
                safe_page=snapshot.get("url"), page_type="security",
            )
        error_text = await _auth_error_text(page)
        if error_text:
            close_profile_timing("error")
            raise CamoufoxBrowserError(
                "free_camoufox_navigation", "打开 Camoufox 注册页面", error_text,
                retryable=not entry_submitted, error_code="camoufox_auth_page_error",
                safe_page=_safe_url(page), page_type=state,
            )
        await asyncio.sleep(1.0)

    # If the global deadline expires while the about-you request is still
    # pending, close any open timing intervals before returning the failure.
    close_profile_timing("timeout")
    raise CamoufoxBrowserError(
        "free_camoufox_page_state", "确认 ChatGPT 登录首页",
        "注册状态机超时，页面未确认进入首页", error_code="camoufox_home_not_confirmed",
        safe_page=_safe_url(page), page_type=await _page_state(page),
    )


@dataclass
class _BrowserSlot:
    manager: Any
    browser: Any
    semaphore: asyncio.Semaphore
    completed: int = 0
    generation: int = 0
    recycle_lock: asyncio.Lock | None = None
    idle_event: asyncio.Event | None = None
    active_contexts: int = 0
    draining: bool = False
    recycle_error: str = ""
    # Contexts retained by the optional debug mode remain attached to the
    # browser until the operator explicitly closes them. They count against
    # the slot's effective capacity even though the task semaphore is released.
    debug_holds: int = 0
    # Playwright may cancel a page coroutine as soon as the browser process
    # disappears, without raising its usual "browser has been closed" error.
    # Keep that signal on the slot so the worker can classify the cancellation
    # instead of exposing a bare concurrent.futures.CancelledError.
    disconnect_requested: bool = False


@dataclass
class _DebugSession:
    """A failed headed context kept available for manual inspection."""

    session_id: str
    task_id: str
    context: Any
    page: Any
    proxy_bridge: Any | None
    slot: _BrowserSlot
    created_at: float
    artifact_id: str = ""
    incident_id: str = ""
    node_code: str = ""
    node_label: str = ""
    error_code: str = ""
    page_type: str = ""
    safe_page: str = ""
    proxy_fingerprint: str = ""
    trace: _DebugTrace | None = None
    artifact_path: str = ""


class _HeldSemaphore:
    """Async context wrapper for a permit acquired by an admission helper."""

    def __init__(self, semaphore: asyncio.Semaphore) -> None:
        self.semaphore = semaphore
        self.released = False

    async def __aenter__(self) -> "_HeldSemaphore":
        return self

    async def __aexit__(self, *_args: Any) -> None:
        if not self.released:
            self.released = True
            self.semaphore.release()


class _SlotAdmissionRace(Exception):
    """Internal signal to rescan the pool after a capacity race."""


class CamoufoxBrowserPool:
    """Dedicated asyncio thread with shared browsers and bounded contexts."""

    def __init__(self, config: Mapping[str, Any]) -> None:
        self.config = dict(config)
        # Debug mode is deliberately enabled by the normalized production
        # config. A retained page must be headed even if an older caller still
        # supplies ``headless=True``.
        self.debug_mode, self.headless = _effective_camoufox_headless(self.config)
        self.pool_size = max(1, int(self.config.get("pool_size") or 2))
        self.max_contexts = max(1, int(self.config.get("max_contexts_per_browser") or 3))
        self.context_start_interval = max(0, int(self.config.get("context_start_interval_ms") or 0)) / 1000.0
        self.startup_concurrency = max(1, int(self.config.get("startup_concurrency") or 4))
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._ready = threading.Event()
        # ``shutdown()`` can be called while the async thread is still
        # initializing.  Keep that request separate from ``_closed`` so the
        # thread can finish its current ``run_until_complete`` before any
        # cleanup coroutine is scheduled.
        self._init_finished = threading.Event()
        self._shutdown_complete = threading.Event()
        self._closed = False
        self._shutdown_requested = threading.Event()
        self._shutdown_task: asyncio.Task[Any] | None = None
        self._init_error: BaseException | None = None
        self._slots: list[_BrowserSlot] = []
        self._global_semaphore: asyncio.Semaphore | None = None
        self._startup_semaphore: asyncio.Semaphore | None = None
        self._context_start_lock: asyncio.Lock | None = None
        self._admission_lock: asyncio.Lock | None = None
        self._next_context_start = 0.0
        self._lock = threading.Lock()
        self._debug_lock = threading.RLock()
        self._debug_sessions: dict[str, _DebugSession] = {}
        self._debug_closing: set[str] = set()
        self._start()

    @staticmethod
    def _task_id_from_kwargs(kwargs: Mapping[str, Any]) -> str:
        nested = kwargs.get("config")
        if isinstance(nested, Mapping):
            value = nested.get("task_id")
            if value:
                return _safe_debug_task_id(value)
        value = kwargs.get("task_id")
        return _safe_debug_task_id(value)

    @staticmethod
    def _page_is_open(page: Any) -> bool:
        if page is None:
            return False
        try:
            checker = getattr(page, "is_closed", None)
            return not bool(checker()) if callable(checker) else True
        except Exception:
            # A page whose state cannot be read is not safe to retain: it is
            # usually already detached from a dead browser process.
            return False

    @staticmethod
    def _debug_retain_allowed(error: BaseException | None) -> bool:
        """Classify terminal errors whose live page is useful to inspect."""
        if error is None:
            return False
        code = str(getattr(error, "error_code", "") or "").strip().lower()
        node = str(getattr(error, "node_code", "") or "").strip().lower()
        page_type = str(getattr(error, "page_type", "") or "").strip().lower()
        if node == "free_run_stop" or code in {
            "free_run_stop", "camoufox_registration_timeout", "camoufox_pool_closed",
            "camoufox_browser_disconnected", "camoufox_context_create_failed",
            "camoufox_page_create_failed", "camoufox_browser_launch_failed",
            "camoufox_home_not_confirmed",
        }:
            return False
        if any(marker in code for marker in ("timeout", "timed_out", "page_state_limit", "page_state_stuck")):
            return False
        if any(marker in code for marker in ("cancel", "stopped", "interrupted")):
            return False
        if code in {
            "free_camoufox_security_challenge",
            "free_oauth_security_challenge",
        } or page_type == "security":
            return True
        return True

    async def _retain_debug_context(
        self,
        *,
        context: Any,
        page: Any,
        proxy_bridge: Any | None,
        slot: _BrowserSlot,
        kwargs: Mapping[str, Any],
        error: BaseException | None = None,
    ) -> bool:
        if not self.debug_mode or not self._page_is_open(page):
            return False
        # The artifact capture below can take several seconds.  During that
        # window the slot may have been disconnected or moved to a replacement
        # browser.  Keep the generation observed for this context and validate
        # it again immediately before installing the debug hold.
        retention_generation = getattr(slot, "generation", 0)
        session_id = f"cam-debug-{uuid.uuid4().hex[:12]}"
        artifact_id = f"cam-artifact-{uuid.uuid4().hex[:12]}"
        nested = kwargs.get("config") if isinstance(kwargs.get("config"), Mapping) else {}
        task_id = self._task_id_from_kwargs(kwargs)
        incident_id = _safe_incident_id(
            getattr(error, "incident_id", "") or nested.get("incident_id")
            or kwargs.get("incident_id")
        )
        node_code = sanitize_failure_text(
            getattr(error, "node_code", "") or nested.get("node_code") or "free_camoufox_browser",
            120,
        )
        node_label = sanitize_failure_text(
            getattr(error, "node_label", "") or nested.get("node_label") or "Camoufox 注册页面",
            160,
        )
        error_code = sanitize_failure_text(
            getattr(error, "error_code", "") or "camoufox_debug_failure", 160,
        )
        page_type = sanitize_failure_text(
            getattr(error, "page_type", "") or "unknown", 80,
        )
        safe_page = _safe_event_url(getattr(error, "safe_page", "") or _safe_url(page)) or "页面地址未知"
        proxy_value = str(kwargs.get("proxy") or nested.get("proxy") or "")
        supplied_fingerprint = nested.get("proxy_fingerprint") or kwargs.get("proxy_fingerprint")
        proxy_fingerprint = _safe_proxy_fingerprint(supplied_fingerprint, proxy_value)
        trace = _page_debug_trace(page)
        artifact_root: Path | None = None
        raw_artifact_root = nested.get("_debug_artifact_dir") or self.config.get("_debug_artifact_dir")
        if raw_artifact_root:
            try:
                artifact_root = Path(str(raw_artifact_root)).expanduser()
            except (TypeError, ValueError, OSError):
                artifact_root = None
        artifact_summary = {
            "task_id": task_id,
            "incident_id": incident_id,
            "node_code": node_code,
            "node_label": node_label,
            "error_code": error_code,
            "page_type": page_type,
            "safe_page": safe_page,
            "proxy_fingerprint": proxy_fingerprint,
            "created_at": time.time(),
        }
        if artifact_root is not None:
            with _ARTIFACT_LOCK:
                _ARTIFACT_PROTECTED_SESSIONS.add(session_id)
        registered = False
        try:
            artifact = await _capture_debug_artifact(
                page=page,
                artifact_root=artifact_root,
                session_id=session_id,
                artifact_id=artifact_id,
                summary=artifact_summary,
                trace=trace,
            )
            session = _DebugSession(
                session_id=session_id,
                task_id=task_id,
                context=context,
                page=page,
                proxy_bridge=proxy_bridge,
                slot=slot,
                created_at=time.time(),
                artifact_id=artifact_id,
                incident_id=incident_id,
                node_code=node_code,
                node_label=node_label,
                error_code=error_code,
                page_type=page_type,
                safe_page=safe_page,
                proxy_fingerprint=proxy_fingerprint,
                trace=trace,
                artifact_path=str(artifact.get("artifact_path") or ""),
            )
            # Register the session and replace the active-context reservation
            # under one admission lock.  The close endpoint and the recycler
            # use this same lock, so neither can observe a session without its
            # capacity hold (or a hold without an owned session).
            if self._admission_lock is not None:
                async with self._admission_lock:
                    slots = getattr(self, "_slots", None)
                    slot_registered = (
                        slots is None
                        or any(candidate is slot for candidate in slots)
                    )
                    if (
                        not self._page_is_open(page)
                        or getattr(self, "_closed", False)
                        or not slot_registered
                        or getattr(slot, "generation", None) != retention_generation
                        or bool(getattr(slot, "draining", False))
                        or not self._browser_connected(getattr(slot, "browser", None))
                    ):
                        return False
                    with self._debug_lock:
                        if session_id not in self._debug_sessions:
                            self._debug_sessions[session_id] = session
                            slot.debug_holds += 1
                            registered = True
            else:
                slots = getattr(self, "_slots", None)
                slot_registered = (
                    slots is None
                    or any(candidate is slot for candidate in slots)
                )
                if (
                    not self._page_is_open(page)
                    or getattr(self, "_closed", False)
                    or not slot_registered
                    or getattr(slot, "generation", None) != retention_generation
                    or bool(getattr(slot, "draining", False))
                    or not self._browser_connected(getattr(slot, "browser", None))
                ):
                    return False
                with self._debug_lock:
                    if session_id not in self._debug_sessions:
                        self._debug_sessions[session_id] = session
                        slot.debug_holds += 1
                        registered = True
        finally:
            if not registered or artifact_root is None:
                with _ARTIFACT_LOCK:
                    _ARTIFACT_PROTECTED_SESSIONS.discard(session_id)
        if error is not None:
            for name, value in (
                ("debug_session_id", session_id),
                ("debug_artifact_id", artifact_id),
                ("artifact_id", artifact_id),
            ):
                try:
                    setattr(error, name, value)
                except Exception:
                    pass
        return True

    async def _close_debug_sessions_async(self, session_id: str = "") -> int:
        normalized = str(session_id or "").strip()
        with self._debug_lock:
            if normalized:
                selected = self._debug_sessions.get(normalized)
                sessions = [selected] if selected is not None and normalized not in self._debug_closing else []
            else:
                sessions = [item for key, item in self._debug_sessions.items() if key not in self._debug_closing]
            self._debug_closing.update(item.session_id for item in sessions if item is not None)
        closed = 0
        slots_to_recycle: list[_BrowserSlot] = []
        timeout = float(self.config.get("context_close_timeout_seconds") or 15)
        try:
            for session in sessions:
                if session is None:
                    continue
                context_closed = False
                try:
                    context_closed = await _close_context_safely(session.context, timeout)
                except asyncio.CancelledError:
                    raise
                except Exception:
                    context_closed = False
                if not context_closed:
                    # A retained page can keep Playwright's context close
                    # waiting after a renderer/network failure. Close the
                    # visible page first, then retry the context once. The
                    # page-level close is sufficient to remove the operator's
                    # window, so do not keep a phantom debug hold if the
                    # detached context itself refuses to close.
                    page_close = getattr(session.page, "close", None)
                    if callable(page_close):
                        try:
                            page_closed = await _close_context_safely(session.page, min(timeout, 5.0))
                        except Exception:
                            page_closed = False
                    else:
                        page_closed = False
                    if page_closed:
                        try:
                            await _close_context_safely(session.context, min(timeout, 5.0))
                        except Exception:
                            pass
                        context_closed = True
                bridge_error = ""
                bridge = session.proxy_bridge
                if bridge is not None and context_closed:
                    try:
                        bridge.close()
                    except Exception as exc:
                        # The context is already gone. Do not retain a phantom
                        # capacity hold solely because the local bridge failed
                        # to stop; keep a bounded marker for postmortem.
                        bridge_error = clean(type(exc).__name__, 120)
                with self._debug_lock:
                    self._debug_closing.discard(session.session_id)
                    if context_closed:
                        self._debug_sessions.pop(session.session_id, None)
                if context_closed:
                    if self._admission_lock is not None:
                        async with self._admission_lock:
                            session.slot.debug_holds = max(0, session.slot.debug_holds - 1)
                    else:
                        session.slot.debug_holds = max(0, session.slot.debug_holds - 1)
                    with _ARTIFACT_LOCK:
                        _ARTIFACT_PROTECTED_SESSIONS.discard(session.session_id)
                    if bridge_error and session.artifact_path:
                        # Incident annotation and bridge cleanup both update
                        # the same summary projection. Serialize the complete
                        # read/modify/write cycle so neither field can be lost
                        # when task failure persistence races window cleanup.
                        with _ARTIFACT_LOCK:
                            try:
                                summary_path = Path(session.artifact_path) / "summary.json"
                                payload = json.loads(summary_path.read_text(encoding="utf-8"))
                                if isinstance(payload, dict):
                                    payload["bridge_cleanup_error"] = bridge_error
                                    _atomic_artifact_write(summary_path, payload)
                            except Exception:
                                pass
                    # A retained context can postpone the normal
                    # max-registrations recycle. Once the final hold on an
                    # otherwise idle slot is released, perform that recycle
                    # before another task is admitted to the old browser.
                    try:
                        max_registrations = max(
                            1, int(self.config.get("max_registrations_per_browser") or 12),
                        )
                    except (TypeError, ValueError):
                        max_registrations = 12
                    if (
                        session.slot.debug_holds == 0
                        and session.slot.active_contexts == 0
                        and (
                            session.slot.completed >= max_registrations
                            or bool(session.slot.recycle_error)
                            or bool(session.slot.draining)
                        )
                        and all(existing is not session.slot for existing in slots_to_recycle)
                    ):
                        slots_to_recycle.append(session.slot)
                    closed += 1
        finally:
            with self._debug_lock:
                self._debug_closing.difference_update(
                    item.session_id for item in sessions if item is not None
                )
        # Run recycling only after all selected sessions have been removed and
        # their capacity holds released. This keeps an all-sessions close
        # request atomic from the pool's admission perspective.
        if not getattr(self, "_closed", False):
            for slot in slots_to_recycle:
                try:
                    await self._recycle_slot(
                        slot,
                        slot.generation,
                        "关闭最后 Camoufox 调试窗口后回收浏览器",
                    )
                except Exception:
                    # Closing a debug window must still report the successful
                    # context close even if a best-effort browser recycle
                    # fails; the next registration will surface recycle_error.
                    continue
        return closed

    async def _discard_debug_sessions_for_slot(self, slot: _BrowserSlot) -> int:
        """Forget unusable sessions after their owning browser disappeared."""
        with self._debug_lock:
            sessions = [
                item for item in self._debug_sessions.values()
                if item.slot is slot
            ]
            for item in sessions:
                self._debug_sessions.pop(item.session_id, None)
                self._debug_closing.discard(item.session_id)
        for session in sessions:
            try:
                await _close_context_safely(session.context, 1.0)
            except Exception:
                pass
            if session.proxy_bridge is not None:
                try:
                    session.proxy_bridge.close()
                except Exception:
                    pass
            with _ARTIFACT_LOCK:
                _ARTIFACT_PROTECTED_SESSIONS.discard(session.session_id)
        if sessions:
            if self._admission_lock is not None:
                async with self._admission_lock:
                    slot.debug_holds = max(0, slot.debug_holds - len(sessions))
            else:
                slot.debug_holds = max(0, slot.debug_holds - len(sessions))
        return len(sessions)

    def _debug_close_timeout_budget(self, session_id: str = "") -> float:
        """Return a bounded wait budget for a synchronous debug close request.

        Contexts are closed serially on the pool loop.  Closing the last hold
        on a slot can then drain active work, tear down the old browser and
        launch a replacement.  A single-context timeout is therefore not a
        sufficient bound for ``close-all`` and can make an otherwise completed
        request look as though it failed while cleanup is still in flight.
        """
        context_timeout = _pool_timeout(self.config, "context_close_timeout_seconds", 15)
        browser_timeout = _pool_timeout(self.config, "browser_recycle_timeout_seconds", 45)
        drain_timeout = _pool_timeout(self.config, "browser_recycle_drain_timeout_seconds", 20)
        normalized = str(session_id or "").strip()
        with self._debug_lock:
            if normalized:
                candidate = self._debug_sessions.get(normalized)
                sessions = (
                    [candidate]
                    if candidate is not None and normalized not in self._debug_closing
                    else []
                )
            else:
                sessions = [
                    item for key, item in self._debug_sessions.items()
                    if key not in self._debug_closing
                ]
        sessions = [item for item in sessions if item is not None]
        if not sessions:
            return max(5.0, context_timeout + 5.0)
        # One slot can only be recycled once after its final retained context
        # closes.  Include both manager teardown and the fallback browser close
        # plus the bounded replacement launch, then add a small scheduling
        # margin for the cross-thread Future handoff.
        slots = {id(item.slot) for item in sessions}
        per_slot_recycle = drain_timeout + (browser_timeout * 2.0) + context_timeout
        return max(
            5.0,
            (len(sessions) * context_timeout)
            + (len(slots) * per_slot_recycle)
            + 5.0,
        )

    def close_debug_sessions(self, session_id: str = "") -> int:
        """Close retained contexts on the pool's asyncio thread.

        The manager and HTTP route run on ordinary worker threads, while page
        and context objects belong to this pool loop.  Always marshal the
        close operation instead of touching Playwright objects cross-thread.
        """
        if self._loop is None or not self._ready.is_set():
            return 0
        timeout = self._debug_close_timeout_budget(session_id)
        try:
            future = asyncio.run_coroutine_threadsafe(
                self._close_debug_sessions_async(session_id), self._loop,
            )
            return int(future.result(timeout=timeout))
        except FutureTimeoutError:
            # The async close path has its own per-resource bounds.  Give it a
            # second, smaller drain window before cancellation so contexts
            # already detached from the task can finish and update debug_state.
            # This keeps a timed-out HTTP request observable instead of
            # leaving a half-closed session with an eagerly cancelled task.
            try:
                return int(future.result(timeout=max(5.0, min(timeout, 30.0))))
            except FutureTimeoutError:
                try:
                    future.cancel()
                except Exception:
                    pass
            except Exception:
                pass
            return 0
        except Exception:
            return 0

    def debug_state(self) -> dict[str, Any]:
        """Return a secret-free snapshot suitable for the public Free state."""
        with self._debug_lock:
            sessions = list(self._debug_sessions.values())
            closing_sessions = {
                item.session_id for item in sessions
                if item.session_id in self._debug_closing
            }
        capacity = max(0, len(self._slots) * self.max_contexts)
        used = sum(max(0, int(slot.active_contexts) + int(slot.debug_holds)) for slot in self._slots)
        return {
            "enabled": bool(self.debug_mode),
            "headless": bool(self.headless),
            "capacity": capacity,
            "used": used,
            "available": max(0, capacity - used),
            "open_contexts": len(sessions),
            "closing_contexts": len(closing_sessions),
            "closing_sessions": sorted(closing_sessions),
            "browser_count": len(self._slots),
            "pool_count": 1,
            "sessions": [
                {
                    "session_id": item.session_id,
                    "task_id": item.task_id,
                    "node_code": item.node_code,
                    "node_label": item.node_label,
                    "error_code": item.error_code,
                    "page_type": item.page_type,
                    "safe_page": item.safe_page,
                    "proxy_fingerprint": item.proxy_fingerprint,
                    "artifact_id": item.artifact_id,
                    "incident_id": item.incident_id,
                    "created_at": item.created_at,
                }
                for item in sessions
            ],
        }

    def has_active_contexts(self) -> bool:
        return any(int(slot.active_contexts) > 0 for slot in self._slots)

    def is_idle(self) -> bool:
        return not self.has_active_contexts() and not self.has_debug_sessions()

    def annotate_debug_session(self, session_id: str, incident_id: str) -> bool:
        """Attach the manager-created incident to a retained debug session."""
        normalized_session = str(session_id or "").strip()
        normalized_incident = _safe_incident_id(incident_id)
        if not normalized_session or not normalized_incident:
            return False
        with self._debug_lock:
            session = self._debug_sessions.get(normalized_session)
            if session is None:
                return False
            session.incident_id = normalized_incident
            artifact_path = session.artifact_path
        if artifact_path:
            # Keep the lock around both read and atomic replace.  Locking only
            # the final write still permits a stale payload to overwrite a
            # bridge-cleanup marker written by the concurrent close path.
            with _ARTIFACT_LOCK:
                try:
                    summary_path = Path(artifact_path) / "summary.json"
                    payload = json.loads(summary_path.read_text(encoding="utf-8"))
                    if isinstance(payload, dict):
                        payload["incident_id"] = normalized_incident
                        _atomic_artifact_write(summary_path, payload)
                except Exception:
                    pass
        return True

    def has_debug_sessions(self) -> bool:
        with self._debug_lock:
            return bool(self._debug_sessions)

    def _start(self) -> None:
        def target() -> None:
            self._loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._loop)
            try:
                try:
                    self._loop.run_until_complete(self._init_async())
                except BaseException as exc:
                    self._init_error = exc
                finally:
                    self._init_finished.set()
                    self._ready.set()
                if self._init_error is None and not self._shutdown_requested.is_set():
                    # A scheduled shutdown task performs cleanup and calls
                    # ``loop.stop`` only after that cleanup has completed.
                    self._loop.run_forever()

                # A shutdown request can arrive during initialization, before
                # ``run_forever`` has started.  In that case no callback can
                # drive the loop, so run the cleanup task synchronously here.
                # Initialization failures use the same path to reclaim any
                # managers opened before the failing slot.
                if not self._shutdown_complete.is_set():
                    shutdown_task = self._shutdown_task
                    if shutdown_task is not None:
                        if not shutdown_task.done():
                            self._loop.run_until_complete(shutdown_task)
                        else:
                            # Surface/consume a cleanup exception without
                            # preventing the completion signal in ``finally``.
                            try:
                                shutdown_task.result()
                            except BaseException:
                                pass
                    else:
                        self._loop.run_until_complete(self._shutdown_async())
                    self._cancel_pending_tasks()
            finally:
                try:
                    self._loop.close()
                finally:
                    # Even an unexpected cleanup exception must make the pool's
                    # completion state observable to the registry.
                    self._shutdown_complete.set()
        self._thread = threading.Thread(target=target, name="gptphone-camoufox", daemon=True)
        self._thread.start()
        self._ready.wait(timeout=90)

    async def _cancel_pending_tasks_async(self) -> None:
        """Cancel registration tasks before closing their browser managers."""
        current = asyncio.current_task()
        pending = [
            task for task in asyncio.all_tasks()
            if task is not current and not task.done()
        ]
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)

    async def _shutdown_and_stop_async(self) -> None:
        """Drain async work, close resources, then release the event loop."""
        try:
            # Force-cancel registration/context tasks first.  Calling
            # ``loop.stop`` before this drain was the source of pending-task
            # warnings and ``Event loop stopped before Future completed`` in
            # the two Camoufox incidents.
            await self._cancel_pending_tasks_async()
            await self._shutdown_async()
        finally:
            loop = self._loop
            if loop is not None and not loop.is_closed():
                loop.stop()

    def _schedule_shutdown(self) -> None:
        """Create the single shutdown task on the pool's asyncio thread."""
        loop = self._loop
        if loop is None or bool(getattr(loop, "is_closed", lambda: False)()):
            return
        task = self._shutdown_task
        if task is None or task.done():
            self._shutdown_task = loop.create_task(self._shutdown_and_stop_async())

    def _cancel_pending_tasks(self) -> None:
        if self._loop is None:
            return
        pending = [task for task in asyncio.all_tasks(self._loop) if not task.done()]
        for task in pending:
            task.cancel()
        if pending:
            self._loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))

    async def _init_async(self) -> None:
        AsyncCamoufox, _ = _load_camoufox_api()
        self._global_semaphore = asyncio.Semaphore(self.pool_size * self.max_contexts)
        self._startup_semaphore = asyncio.Semaphore(min(self.startup_concurrency, self.pool_size * self.max_contexts))
        self._context_start_lock = asyncio.Lock()
        self._admission_lock = asyncio.Lock()
        async def launch_slot(_index: int) -> tuple[int, Any, Any]:
            manager, browser = await self._launch_browser()
            return _index, manager, browser

        results = await asyncio.gather(
            *(launch_slot(index) for index in range(self.pool_size)),
            return_exceptions=True,
        )
        failures = [item for item in results if isinstance(item, BaseException)]
        if failures:
            close_timeout = _pool_timeout(self.config, "browser_recycle_timeout_seconds", 45)
            for item in results:
                if isinstance(item, BaseException):
                    continue
                _index, manager, browser = item
                manager_closed = True
                if manager is not None:
                    manager_closed = await _close_async_resource(
                        lambda manager=manager: manager.__aexit__(None, None, None),
                        close_timeout,
                    )
                if not manager_closed and browser is not None:
                    await _close_async_resource(browser.close, close_timeout)
            failure = failures[0]
            if isinstance(failure, CamoufoxBrowserError):
                raise failure
            raise CamoufoxBrowserError(
                "free_camoufox_launch", "启动 Camoufox 浏览器池",
                "Camoufox 浏览器池启动失败",
                error_code="camoufox_browser_launch_failed",
                diagnostic=type(failure).__name__,
            ) from failure

        for result in sorted(results, key=lambda item: item[0]):
            _index, manager, browser = result
            slot = _BrowserSlot(
                manager, browser, asyncio.Semaphore(self.max_contexts),
                recycle_lock=asyncio.Lock(), idle_event=asyncio.Event(),
            )
            self._slots.append(slot)
            self._attach_browser_disconnect(slot)
            slot.idle_event.set()

    def _attach_browser_disconnect(self, slot: _BrowserSlot) -> None:
        """Schedule pool recovery when Playwright reports a dead browser."""
        browser = slot.browser
        on = getattr(browser, "on", None)
        if not callable(on):
            return
        generation = slot.generation

        def disconnected(*_args: Any, **_kwargs: Any) -> None:
            loop = self._loop
            if loop is None or self._closed:
                return

            def schedule_recycle() -> None:
                # A stale listener from a retired browser can fire after the
                # slot has already been replaced.  Do not mark the new browser
                # as disconnected in that case.
                if (
                    self._closed
                    or slot.generation != generation
                    or slot.browser is not browser
                ):
                    return
                slot.disconnect_requested = True
                try:
                    asyncio.create_task(
                        self._recycle_slot(slot, generation, "Camoufox 浏览器断开事件")
                    )
                except Exception:
                    pass

            try:
                loop.call_soon_threadsafe(schedule_recycle)
            except Exception:
                pass

        try:
            on("disconnected", disconnected)
        except Exception:
            pass

    async def _launch_browser(self) -> tuple[Any, Any]:
        AsyncCamoufox, _ = _load_camoufox_api()
        last_error: BaseException | None = None
        attempts = max(1, int(self.config.get("browser_launch_attempts") or 3))
        for attempt in range(attempts):
            launch_options = {
                "headless": self.headless,
                "block_images": bool(self.config.get("block_images", True) and self.headless),
                "enable_cache": False,
            }
            if launch_options["block_images"]:
                # Camoufox requires an explicit acknowledgement because image
                # blocking can affect WAF detection and page behavior.
                launch_options["i_know_what_im_doing"] = True
            manager = AsyncCamoufox(
                **launch_options,
            )
            try:
                if self._startup_semaphore is None:
                    browser = await manager.__aenter__()
                else:
                    async with self._startup_semaphore:
                        browser = await manager.__aenter__()
                return manager, browser
            except BaseException as exc:
                last_error = exc
                try:
                    await manager.__aexit__(type(exc), exc, exc.__traceback__)
                except Exception:
                    pass
                if attempt + 1 < attempts:
                    await asyncio.sleep(min(2 ** attempt, 5))
        raise CamoufoxBrowserError(
            "free_camoufox_launch", "启动 Camoufox 浏览器池",
            "Camoufox 浏览器进程启动失败",
            error_code="camoufox_browser_launch_failed",
            diagnostic=type(last_error).__name__ if last_error else "unknown",
        ) from last_error

    async def _shutdown_async(self) -> None:
        # Debug sessions own live contexts and proxy bridges. Close them before
        # their browser managers so no bridge/thread survives pool shutdown.
        await self._close_debug_sessions_async()
        # A disconnected context may refuse close; once the pool itself is
        # shutting down there is no live window to preserve, so clear the
        # registry and holds rather than leaving stale capacity in state.
        for slot in list(self._slots):
            if slot.debug_holds:
                await self._discard_debug_sessions_for_slot(slot)
        slots, self._slots = self._slots, []
        for slot in slots:
            manager = slot.manager
            browser = slot.browser
            manager_timeout = float(self.config.get("browser_recycle_timeout_seconds") or 45)
            browser_timeout = float(self.config.get("context_close_timeout_seconds") or 15)
            manager_closed = True
            if manager is not None:
                manager_closed = await _close_async_resource(
                    lambda manager=manager: manager.__aexit__(None, None, None),
                    manager_timeout,
                )
            if (manager is None or not manager_closed) and browser is not None:
                await _close_async_resource(browser.close, browser_timeout)

    async def _register_async(self, kwargs: Mapping[str, Any]) -> dict[str, Any]:
        if self._global_semaphore is None or not self._slots:
            raise CamoufoxBrowserError("free_camoufox_launch", "启动 Camoufox", "浏览器池没有可用进程", error_code="camoufox_pool_empty")
        registration_timeout = float(self.config.get("registration_timeout_seconds") or 600)
        fallback_deadline = time.monotonic() + max(0.0, registration_timeout)
        controller = kwargs.get("deadline_controller")
        if controller is None:
            supplied_config = kwargs.get("config")
            if isinstance(supplied_config, Mapping):
                controller = supplied_config.get("_deadline_controller")
        if controller is None:
            controller = RegistrationDeadline(registration_timeout)
        effective_kwargs = dict(kwargs)
        effective_config = dict(kwargs.get("config") or {})
        effective_config["_deadline_controller"] = controller
        effective_kwargs["config"] = effective_config
        effective_kwargs["deadline_controller"] = controller
        restart_attempted = False
        while True:
            try:
                async with self._global_semaphore:
                    task = asyncio.create_task(self._register_with_slot(effective_kwargs))
                    safety_deadline = time.monotonic() + registration_timeout + max(
                        30.0,
                        float(self.config.get("context_close_timeout_seconds") or 15)
                        + float(self.config.get("browser_recycle_timeout_seconds") or 45)
                        + float(self.config.get("browser_recycle_drain_timeout_seconds") or 20)
                        + (MANUAL_OTP_WINDOW_SECONDS * MAX_MANUAL_OTP_WINDOWS)
                        + MANUAL_OTP_POST_SUBMIT_GRACE_SECONDS,
                    )
                    try:
                        while True:
                            if task.done():
                                return await task
                            expired_value = _deadline_controller_call(controller, "is_expired")
                            if expired_value is _DEADLINE_CONTROLLER_MISSING:
                                expired = time.monotonic() >= fallback_deadline
                            else:
                                try:
                                    expired = bool(expired_value)
                                except Exception:
                                    expired = time.monotonic() >= fallback_deadline
                            paused = _deadline_controller_bool(controller, "is_paused")
                            prompt_active = _deadline_controller_bool(controller, "manual_prompt_active")
                            handoff_active = _deadline_controller_bool(controller, "manual_handoff_active")
                            post_submit_grace = _deadline_controller_bool(controller, "manual_submission_grace_active")
                            otp_wait_active = _deadline_controller_bool(controller, "otp_wait_active")
                            remaining_value = _deadline_controller_call(controller, "remaining")
                            if remaining_value is _DEADLINE_CONTROLLER_MISSING:
                                remaining = max(0.0, fallback_deadline - time.monotonic())
                            else:
                                try:
                                    remaining = float(remaining_value)
                                    if not math.isfinite(remaining):
                                        raise ValueError
                                except (TypeError, ValueError, OverflowError):
                                    remaining = max(0.0, fallback_deadline - time.monotonic())
                            if expired and otp_wait_active and not paused and not handoff_active:
                                requested_handoff = _deadline_controller_call(
                                    controller, "request_manual_handoff"
                                )
                                if requested_handoff is not _DEADLINE_CONTROLLER_MISSING:
                                    paused = True
                                    handoff_active = True
                            if (
                                (
                                    expired
                                    and not (paused or prompt_active or handoff_active or post_submit_grace)
                                )
                                or (
                                    paused
                                    and otp_wait_active
                                    and not (prompt_active or handoff_active or post_submit_grace)
                                )
                                or time.monotonic() >= safety_deadline
                            ):
                                if paused and not prompt_active and not handoff_active:
                                    _deadline_controller_call(controller, "resume_manual", "timeout")
                                task.cancel()
                                try:
                                    await asyncio.wait_for(
                                        asyncio.shield(task),
                                        timeout=max(1.0, min(30.0, safety_deadline - time.monotonic() + 1.0)),
                                    )
                                except BaseException:
                                    pass
                                raise CamoufoxBrowserError(
                                    "free_camoufox_browser", "Camoufox 注册页面",
                                    "浏览器注册超时，已取消当前 context 并回收进程",
                                    error_code="camoufox_registration_timeout",
                                )
                            await asyncio.sleep(
                                min(0.25, max(0.01, remaining)) if not paused
                                else 0.25
                            )
                    finally:
                        if not task.done():
                            task.cancel()
                        try:
                            await asyncio.wait_for(asyncio.shield(task), timeout=5.0)
                        except BaseException:
                            pass
            except asyncio.TimeoutError as exc:
                raise CamoufoxBrowserError(
                    "free_camoufox_browser", "Camoufox 注册页面",
                    "浏览器注册超时，已取消当前 context 并回收进程",
                    error_code="camoufox_registration_timeout",
                ) from exc
            except CamoufoxBrowserError as exc:
                # Context/page creation failures happen before the remote
                # signup page exists and are safe to retry once after the pool
                # has recycled the disconnected process.  Once navigation has
                # started, preserve the original failure to avoid replaying a
                # potentially submitted signup.
                if (
                    not restart_attempted
                    and getattr(exc, "safe_restart", False)
                    and exc.error_code in {
                        "camoufox_browser_disconnected",
                        "camoufox_context_create_failed",
                        "camoufox_page_create_failed",
                        "camoufox_browser_recycle_failed",
                    }
                ):
                    restart_attempted = True
                    await asyncio.sleep(0.2)
                    continue
                raise

    @staticmethod
    def _browser_connected(browser: Any) -> bool:
        try:
            checker = getattr(browser, "is_connected", None)
            return bool(checker()) if callable(checker) else browser is not None
        except Exception:
            return False

    async def _wait_context_start_slot(self) -> None:
        if self.context_start_interval <= 0 or self._context_start_lock is None:
            return
        async with self._context_start_lock:
            now = asyncio.get_running_loop().time()
            if self._next_context_start > now:
                await asyncio.sleep(self._next_context_start - now)
            self._next_context_start = asyncio.get_running_loop().time() + self.context_start_interval

    async def _release_active_context(
        self,
        slot: _BrowserSlot,
        *,
        debug_retained: bool,
        debug_context: Any | None = None,
        debug_hold_registered: bool = False,
    ) -> None:
        """Release the admission reservation after task cleanup completes.

        Closing a retained context is marshalled onto this same asyncio loop,
        but it can still run between the retention coroutine and this final
        bookkeeping step.  Only add a debug hold while the context is still
        registered; otherwise a close that already removed the session would
        leave an unowned capacity reservation behind.
        """
        # New retention calls atomically install their hold before this method
        # runs.  ``debug_hold_registered`` prevents a concurrent close from
        # being undone by the worker's final bookkeeping.  The fallback path
        # remains for older direct callers that only registered a session.
        retain_hold = bool(debug_retained) and not debug_hold_registered
        if retain_hold:
            sessions = getattr(self, "_debug_sessions", None)
            if isinstance(sessions, dict):
                debug_lock = getattr(self, "_debug_lock", None)
                if debug_lock is not None:
                    with debug_lock:
                        retain_hold = any(
                            item is not None
                            and (debug_context is None or getattr(item, "context", None) is debug_context)
                            for item in sessions.values()
                        )
                else:
                    retain_hold = any(
                        item is not None
                        and (debug_context is None or getattr(item, "context", None) is debug_context)
                        for item in sessions.values()
                    )
        if self._admission_lock is not None:
            async with self._admission_lock:
                slot.active_contexts = max(0, slot.active_contexts - 1)
                if retain_hold:
                    slot.debug_holds += 1
                if slot.active_contexts == 0 and slot.idle_event is not None:
                    slot.idle_event.set()
        else:
            slot.active_contexts = max(0, slot.active_contexts - 1)
            if retain_hold:
                slot.debug_holds += 1
            if slot.active_contexts == 0 and slot.idle_event is not None:
                slot.idle_event.set()

    async def _acquire_slot_permit(self, slot: _BrowserSlot) -> _HeldSemaphore | None:
        """Atomically reserve one active context and its semaphore permit.

        Debug contexts release the task semaphore while remaining attached to
        the browser.  The active-context reservation therefore has to happen
        under the same admission lock as the debug-hold check; otherwise two
        waiters can both observe the same free capacity and overbook a slot.
        """
        await slot.semaphore.acquire()
        reserved = False
        try:
            if self._admission_lock is not None:
                async with self._admission_lock:
                    available = (
                        not slot.draining
                        and not (
                            slot.recycle_lock is not None
                            and slot.recycle_lock.locked()
                        )
                        and slot.active_contexts + slot.debug_holds < self.max_contexts
                    )
                    if available:
                        slot.active_contexts += 1
                        reserved = True
                        if slot.idle_event is not None:
                            slot.idle_event.clear()
            else:
                available = (
                    not slot.draining
                    and not (
                        slot.recycle_lock is not None
                        and slot.recycle_lock.locked()
                    )
                    and slot.active_contexts + slot.debug_holds < self.max_contexts
                )
                if available:
                    slot.active_contexts += 1
                    reserved = True
                    if slot.idle_event is not None:
                        slot.idle_event.clear()
            if available:
                return _HeldSemaphore(slot.semaphore)
        except BaseException:
            if reserved:
                await self._release_active_context(slot, debug_retained=False)
            slot.semaphore.release()
            raise
        slot.semaphore.release()
        return None

    async def _register_with_slot(self, kwargs: Mapping[str, Any]) -> dict[str, Any]:
        while True:
            try:
                return await self._register_with_slot_once(kwargs)
            except _SlotAdmissionRace:
                await asyncio.sleep(0)

    async def _register_with_slot_once(self, kwargs: Mapping[str, Any]) -> dict[str, Any]:
        timing_fn = kwargs.get("timing_fn")
        admission_started = time.monotonic()
        recovery_attempted = False
        while True:
            available = [
                slot for slot in self._slots
                if not slot.draining
                and not (
                    slot.recycle_lock is not None
                    and slot.recycle_lock.locked()
                )
                and self._browser_connected(slot.browser)
            ]
            if available:
                # Retained debug contexts stay open and consume a real browser
                # context slot even after their task Future has completed.
                idle = [
                    item for item in available
                    if not item.semaphore.locked()
                    and item.active_contexts + item.debug_holds < self.max_contexts
                ]
                if idle:
                    slot = min(
                        idle,
                        key=lambda item: (
                            item.active_contexts + item.debug_holds,
                            item.completed,
                        ),
                    )
                    break
                await asyncio.sleep(0.05)
                continue
            # A disconnect callback or registration-limit cleanup can already
            # be rebuilding every slot.  Treat that as a transient admission
            # state and let the in-flight recycler finish.  The old code set
            # ``recovery_attempted`` before finding a candidate and immediately
            # reported ``browser_disconnected`` here, which raced the normal
            # replacement launch and caused the RNBG5WMB failure.
            recycling = [
                slot for slot in self._slots
                if slot.draining or (
                    slot.recycle_lock is not None
                    and slot.recycle_lock.locked()
                )
            ]
            # A recycler owns the slot lock for its entire close/launch cycle.
            # Keep admission waiting while any candidate is in that cycle. A
            # completed-but-draining slot with an explicit recycle error is
            # already terminal for this pool and should retain the existing
            # structured ``recycle_failed`` result; a draining slot without
            # an error is handed to the recovery branch below.
            if any(
                slot.recycle_lock is not None and slot.recycle_lock.locked()
                for slot in recycling
            ):
                await asyncio.sleep(0.2)
                continue
            if any(slot.recycle_error for slot in recycling):
                failure = CamoufoxBrowserError(
                    "free_camoufox_launch", "启动 Camoufox 浏览器池",
                    "Camoufox 浏览器进程回收后重新启动失败",
                    retryable=True, error_code="camoufox_browser_recycle_failed",
                    diagnostic=next(
                        slot.recycle_error for slot in recycling if slot.recycle_error
                    ),
                )
                setattr(failure, "safe_restart", True)
                raise failure
            # A browser can disappear between the health check and context
            # creation.  Rebuild one disconnected slot before reporting that
            # the pool is empty; this mirrors the reference pool's admission
            # recovery and prevents a transient process exit from consuming a
            # whole task.
            if not recovery_attempted:
                recoverable = next(
                    (
                        slot for slot in self._slots
                        if slot.recycle_lock is None or not slot.recycle_lock.locked()
                    ),
                    None,
                )
                if recoverable is not None:
                    recovery_attempted = True
                    generation = recoverable.generation
                    await self._recycle_slot(recoverable, generation, "浏览器池没有可用进程")
                    continue
            recycle_errors = [slot.recycle_error for slot in self._slots if slot.recycle_error]
            if recycle_errors:
                failure = CamoufoxBrowserError(
                    "free_camoufox_launch", "启动 Camoufox 浏览器池",
                    "Camoufox 浏览器进程回收后重新启动失败",
                    retryable=True, error_code="camoufox_browser_recycle_failed",
                    diagnostic=recycle_errors[0],
                )
                setattr(failure, "safe_restart", True)
                raise failure
            failure = CamoufoxBrowserError(
                "free_camoufox_launch", "启动 Camoufox",
                "浏览器池没有可用进程", error_code="camoufox_browser_disconnected",
                retryable=True,
            )
            setattr(failure, "safe_restart", True)
            raise failure
        permit = await self._acquire_slot_permit(slot)
        if permit is None:
            # A debug context may have been retained after the slot selection;
            # return to the pool scan so another browser can admit this task.
            raise _SlotAdmissionRace()
        emit_timing(
            timing_fn,
            "free_camoufox_signup",
            "camoufox_pool_admission",
            (time.monotonic() - admission_started) * 1000,
            "success",
        )
        async with permit:
            recycle_required = False
            generation = slot.generation
            context = None
            page = None
            proxy_bridge: Socks5HttpBridge | None = None
            debug_failure = False
            debug_retain_allowed = True
            debug_retained = False
            debug_error: BaseException | None = None
            trace: _DebugTrace | None = None
            try:
                if slot.draining or not self._browser_connected(slot.browser):
                    recycle_required = True
                    failure = CamoufoxBrowserError(
                        "free_camoufox_launch", "启动 Camoufox",
                        "浏览器进程已断开", error_code="camoufox_browser_disconnected",
                        retryable=True,
                    )
                    setattr(failure, "safe_restart", True)
                    raise failure
                context_started = time.monotonic()
                try:
                    await self._wait_context_start_slot()
                    context_proxy = _proxy_config(str(kwargs.get("proxy") or ""))
                    if (
                        context_proxy
                        and context_proxy.get("username")
                        and context_proxy.get("password")
                        and str(context_proxy.get("server") or "").lower().startswith(("socks5://", "socks5h://"))
                    ):
                        proxy_bridge = Socks5HttpBridge(str(kwargs.get("proxy") or ""))
                        context_proxy = proxy_bridge.proxy_config
                    context = await _new_context(
                        slot.browser,
                        proxy=context_proxy,
                    )
                    emit_timing(
                        timing_fn,
                        "free_camoufox_signup",
                        "camoufox_context_create",
                        (time.monotonic() - context_started) * 1000,
                        "success",
                    )
                except CamoufoxBrowserError:
                    emit_timing(
                        timing_fn,
                        "free_camoufox_signup",
                        "camoufox_context_create",
                        (time.monotonic() - context_started) * 1000,
                        "error",
                    )
                    raise
                except Exception as exc:
                    emit_timing(
                        timing_fn,
                        "free_camoufox_signup",
                        "camoufox_context_create",
                        (time.monotonic() - context_started) * 1000,
                        "error",
                    )
                    recycle_required = True
                    if _browser_process_lost(exc):
                        recycle_required = True
                        failure = CamoufoxBrowserError(
                            "free_camoufox_launch", "创建 Camoufox 浏览器 context",
                            "Camoufox 浏览器进程无法创建 context",
                            error_code="camoufox_context_create_failed",
                            diagnostic="browser process lost",
                        )
                        setattr(failure, "safe_restart", True)
                        raise failure from exc
                    failure = CamoufoxBrowserError(
                        "free_camoufox_launch", "创建 Camoufox 浏览器 context",
                        "Camoufox context 创建失败",
                        error_code="camoufox_context_create_failed",
                        diagnostic=_context_failure_diagnostic(exc),
                    )
                    # Context creation is before any email submission. With
                    # an explicit task proxy, a non-runtime context error can
                    # safely switch to a healthy pool entry and replay the
                    # untouched task. Browser-runtime errors must stay local
                    # so they are not misreported as proxy health failures.
                    setattr(
                        failure,
                        "proxy_retryable",
                        bool(kwargs.get("proxy"))
                        and "reason=proxy_or_transport" in failure.diagnostic,
                    )
                    raise failure from exc
                page_started = time.monotonic()
                try:
                    page = await context.new_page()
                    emit_timing(
                        timing_fn,
                        "free_camoufox_signup",
                        "camoufox_page_create",
                        (time.monotonic() - page_started) * 1000,
                        "success",
                    )
                except Exception as exc:
                    emit_timing(
                        timing_fn,
                        "free_camoufox_signup",
                        "camoufox_page_create",
                        (time.monotonic() - page_started) * 1000,
                        "error",
                    )
                    recycle_required = True
                    if _browser_process_lost(exc):
                        recycle_required = True
                        failure = CamoufoxBrowserError(
                            "free_camoufox_launch", "创建 Camoufox 注册页面",
                            "Camoufox 浏览器进程无法创建页面",
                            error_code="camoufox_page_create_failed",
                            diagnostic="browser process lost",
                        )
                        setattr(failure, "safe_restart", True)
                        raise failure from exc
                    raise CamoufoxBrowserError(
                        "free_camoufox_launch", "创建 Camoufox 注册页面",
                        "Camoufox context 无法创建页面",
                        error_code="camoufox_page_create_failed",
                        diagnostic=type(exc).__name__,
                    ) from exc
                trace = _page_debug_trace(page)
                flow_kwargs = dict(kwargs)
                flow_kwargs.setdefault("startup_gate", self._startup_semaphore)
                result = await _browser_flow(page, **flow_kwargs)
                slot.completed += 1
                recycle_required = slot.completed >= max(1, int(self.config.get("max_registrations_per_browser") or 12))
                return result
            except asyncio.CancelledError as exc:
                # ``asyncio.wait_for`` cancels this coroutine for a normal
                # registration timeout, but Playwright can also cancel it when
                # the Firefox process disappears.  The latter has an empty
                # exception message, so relying on ``_browser_process_lost``
                # alone turns into a bare concurrent.futures.CancelledError
                # at the synchronous pool boundary.  Use the slot health and
                # disconnect callback marker to preserve a stable node.
                recycle_required = True
                debug_failure = True
                debug_retain_allowed = False
                if self._closed:
                    failure = CamoufoxBrowserError(
                        "free_camoufox_launch", "启动 Camoufox 浏览器池",
                        "Camoufox 浏览器池已关闭，当前注册被取消",
                        retryable=False,
                        error_code="camoufox_pool_closed",
                        diagnostic="cancellation_source=pool_shutdown",
                        safe_page=_safe_url(page) if page is not None else "",
                        page_type="unknown",
                    )
                    _mark_recycle_required(failure, "pool closed during registration")
                    debug_error = failure
                    raise failure from exc
                browser_disconnected = bool(
                    getattr(slot, "disconnect_requested", False)
                ) or not self._browser_connected(getattr(slot, "browser", None))
                if browser_disconnected:
                    failure = CamoufoxBrowserError(
                        "free_camoufox_launch", "启动 Camoufox 浏览器池",
                        "Camoufox 浏览器进程在注册过程中退出",
                        retryable=True,
                        error_code="camoufox_browser_disconnected",
                        diagnostic="cancellation_source=browser_disconnect; browser_process_lost=true",
                        safe_page=_safe_url(page) if page is not None else "",
                        page_type="unknown",
                    )
                    # The page may already have submitted an email/OTP when
                    # the process vanished.  Never replay the whole flow from
                    # this path, even though the browser pool itself is
                    # recycled for the next task.
                    setattr(failure, "safe_restart", False)
                    _mark_recycle_required(failure, "browser process lost during registration")
                    debug_error = failure
                    raise failure from exc
                # Leave an ordinary timeout/external cancellation untouched so
                # the surrounding wait_for (or caller) can classify it as a
                # timeout/stop rather than incorrectly blaming the browser.
                debug_error = None
                raise
            except CamoufoxBrowserError as exc:
                debug_failure = True
                debug_error = exc
                if getattr(exc, "recycle_required", False) or exc.error_code in {
                    "camoufox_browser_disconnected",
                    "camoufox_context_create_failed",
                    "camoufox_page_create_failed",
                }:
                    recycle_required = True
                    debug_retain_allowed = False
                elif not self._debug_retain_allowed(exc):
                    debug_retain_allowed = False
                raise
            except FreeRegisterError as exc:
                debug_failure = True
                debug_error = exc
                if not self._debug_retain_allowed(exc):
                    debug_retain_allowed = False
                raise
            except Exception as exc:
                debug_failure = True
                debug_error = exc
                safe_page = _safe_url(page) if page is not None else ""
                page_type = "unknown"
                if page is not None:
                    try:
                        page_type = await _page_state(page)
                    except Exception:
                        page_type = "unknown"
                if isinstance(exc, (asyncio.TimeoutError, TimeoutError, FutureTimeoutError)):
                    recycle_required = True
                    debug_retain_allowed = False
                    failure = CamoufoxBrowserError(
                        "free_camoufox_page_state", "Camoufox 注册页面",
                        "Camoufox 浏览器流程超时，已回收当前 context",
                        retryable=True,
                        error_code="camoufox_browser_flow_timeout",
                        diagnostic=f"exception_type={type(exc).__name__}; safe_page={safe_page}; page_type={page_type}",
                        safe_page=safe_page,
                        page_type=page_type,
                    )
                    _mark_recycle_required(failure, "generic flow timeout")
                    debug_error = failure
                    raise failure from exc
                if _browser_process_lost(exc):
                    recycle_required = True
                    debug_retain_allowed = False
                    failure = CamoufoxBrowserError(
                        "free_camoufox_launch", "启动 Camoufox 浏览器池",
                        "Camoufox 浏览器进程已断开",
                        error_code="camoufox_browser_disconnected",
                        diagnostic="browser process lost",
                        safe_page=safe_page, page_type=page_type,
                    )
                    setattr(failure, "safe_restart", False)
                    debug_error = failure
                    raise failure from exc
                failure = CamoufoxBrowserError(
                    "free_camoufox_browser", "Camoufox 注册页面", f"浏览器流程异常（{type(exc).__name__}）",
                    error_code="camoufox_browser_flow_failed",
                    diagnostic=json.dumps({
                        "exception": type(exc).__name__,
                        "detail": _camoufox_error_detail(exc),
                        "kwargs": sorted(str(key) for key in kwargs.keys()),
                        "safe_page": safe_page,
                        "page_type": page_type,
                    }, ensure_ascii=False)[:500],
                    safe_page=safe_page, page_type=page_type,
                )
                debug_error = failure
                raise failure from exc
            finally:
                if context is not None and debug_failure and debug_retain_allowed:
                    try:
                        debug_retained = await self._retain_debug_context(
                            context=context,
                            page=page,
                            proxy_bridge=proxy_bridge,
                            slot=slot,
                            kwargs=kwargs,
                            error=debug_error,
                        )
                    except Exception:
                        # Retention is diagnostic-only; never mask the actual
                        # registration failure if a fake/old Playwright API
                        # rejects the inspection hook.
                        debug_retained = False
                if context is not None and not debug_retained:
                    closed = await _close_context_safely(
                        context,
                        float(self.config.get("context_close_timeout_seconds") or 15),
                    )
                    if not closed:
                        recycle_required = True
                if proxy_bridge is not None and not debug_retained:
                    try:
                        proxy_bridge.close()
                    except Exception:
                        recycle_required = True
                if debug_retained:
                    # Keep the browser process and its page available for the
                    # operator; ordinary per-task cleanup must not trigger a
                    # recycle behind the scenes.
                    recycle_required = False
                await self._release_active_context(
                    slot,
                    debug_retained=debug_retained,
                    debug_context=context,
                    debug_hold_registered=debug_retained,
                )
                if recycle_required and generation == slot.generation and not self._closed:
                    await self._recycle_slot(slot, generation, "达到单进程注册上限或 context 关闭异常")

    async def _recycle_slot(self, slot: _BrowserSlot, generation: int, reason: str) -> None:
        lock = slot.recycle_lock
        if lock is None:
            return
        async with lock:
            if slot.generation != generation or self._closed:
                return
            old_manager, old_browser = slot.manager, slot.browser
            replacement_committed = False
            replacement_ready = False
            # Mark the slot as draining before any await.  Retention checks the
            # same admission lock, so a disconnect/recycle cannot admit a new
            # debug hold after the dead-browser check but before teardown.
            if self._admission_lock is not None:
                async with self._admission_lock:
                    if slot.generation != generation or self._closed:
                        return
                    slot.draining = True
            else:
                slot.draining = True

            async def close_resource(
                close_fn: Callable[[], Any], timeout: float,
            ) -> tuple[bool, bool]:
                """Close one async browser resource and report cancellation.

                ``asyncio.wait_for`` normally cancels its child when the
                surrounding recycle task is cancelled.  Keep that child in a
                task and shield it so we can finish (or explicitly cancel) the
                manager close before propagating cancellation; otherwise the
                slot has already detached its only reference to the old
                browser.
                """
                try:
                    result = close_fn()
                except asyncio.CancelledError:
                    return False, True
                except BaseException:
                    return False, False
                if not inspect.isawaitable(result):
                    return True, False
                task = asyncio.create_task(result)
                budget = max(0.1, float(timeout))
                try:
                    await asyncio.wait_for(asyncio.shield(task), timeout=budget)
                    return True, False
                except asyncio.TimeoutError:
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
                    return False, False
                except asyncio.CancelledError:
                    # The caller's cancellation is intentionally deferred
                    # until the child has had a bounded chance to finish.
                    try:
                        await asyncio.wait_for(asyncio.shield(task), timeout=budget)
                    except asyncio.TimeoutError:
                        task.cancel()
                        await asyncio.gather(task, return_exceptions=True)
                    except BaseException:
                        task.cancel()
                        await asyncio.gather(task, return_exceptions=True)
                    return False, True
                except BaseException:
                    return False, False

            try:
                if slot.browser is None or not self._browser_connected(slot.browser):
                    # A dead browser cannot keep a headed inspection window
                    # alive. Remove those holds before recycling so the slot
                    # cannot remain permanently full after a process exit.
                    await self._discard_debug_sessions_for_slot(slot)
                # A debug page is intentionally the last live artifact of a
                # failed task. Do not tear down its browser behind the
                # operator's back; the explicit close endpoint will release
                # the hold and perform the normal pool shutdown.
                if slot.debug_holds:
                    slot.draining = False
                    slot.recycle_error = ""
                    return
                if slot.active_contexts and slot.idle_event is not None:
                    try:
                        await asyncio.wait_for(
                            slot.idle_event.wait(),
                            timeout=float(self.config.get("browser_recycle_drain_timeout_seconds") or 20),
                        )
                    except asyncio.TimeoutError:
                        pass
                # A task that was already in its terminal cleanup can retain a
                # debug page while the drain event is being awaited. Re-check
                # immediately before touching the old browser; otherwise the
                # newly retained page could be closed behind the operator.
                if self._admission_lock is not None:
                    async with self._admission_lock:
                        if slot.debug_holds:
                            slot.draining = False
                            slot.recycle_error = ""
                            return
                elif slot.debug_holds:
                    slot.draining = False
                    slot.recycle_error = ""
                    return
                # Mark the slot as replaced only after the drain check. If
                # cancellation arrives during the wait, the finally block
                # restores draining=False on the still-usable old browser.
                slot.manager = None
                slot.browser = None
                slot.generation += 1
                slot.completed = 0
                replacement_committed = True
                close_cancelled = False
                resource_closed = False
                close_timeout = float(self.config.get("browser_recycle_timeout_seconds") or 45)
                if old_manager is not None:
                    resource_closed, close_cancelled = await close_resource(
                        lambda: old_manager.__aexit__(None, None, None),
                        close_timeout,
                    )
                if old_browser is not None and (not resource_closed or old_manager is None):
                    _browser_closed, browser_cancelled = await close_resource(
                        old_browser.close,
                        float(self.config.get("context_close_timeout_seconds") or 15),
                    )
                    resource_closed = bool(resource_closed or _browser_closed)
                    close_cancelled = bool(close_cancelled or browser_cancelled)
                if close_cancelled:
                    raise asyncio.CancelledError
                if self._closed:
                    return
                try:
                    manager, browser = await asyncio.wait_for(
                        self._launch_browser(),
                        timeout=float(self.config.get("browser_recycle_timeout_seconds") or 45),
                    )
                except Exception as exc:
                    slot.draining = True
                    error_code = str(getattr(exc, "error_code", "") or type(exc).__name__)
                    slot.recycle_error = clean(f"{error_code}: {type(exc).__name__}", 240)
                    return
                slot.manager, slot.browser, slot.draining, slot.recycle_error = manager, browser, False, ""
                # The disconnect marker belongs to the old browser generation;
                # clear it only after a replacement is fully attached so a
                # cancellation during the launch window still reports the
                # unavailable slot accurately.
                slot.disconnect_requested = False
                replacement_ready = True
                self._attach_browser_disconnect(slot)
            finally:
                if (
                    not replacement_committed
                    and slot.generation == generation
                    and slot.browser is old_browser
                    and not self._closed
                ):
                    # Cancellation during the drain wait leaves the original
                    # browser usable; make that fact visible to admission.
                    slot.draining = False
                    if self._browser_connected(old_browser):
                        # A stale/duplicate disconnect callback must not make
                        # a later, unrelated task cancellation look like a
                        # browser crash after the old slot is restored.
                        slot.disconnect_requested = False
                elif (
                    replacement_committed
                    and not replacement_ready
                    and slot.generation == generation + 1
                    and not self._closed
                    and slot.browser is None
                ):
                    # The old browser was detached but replacement did not
                    # finish. Keep the slot blocked and expose a stable error
                    # for the next registration instead of accepting work on
                    # a half-recycled slot.
                    slot.draining = True
                    if not slot.recycle_error:
                        slot.recycle_error = "browser_recycle_incomplete"

    def register(self, **kwargs: Any) -> dict[str, Any]:
        if self._closed:
            raise CamoufoxBrowserError("free_camoufox_launch", "启动 Camoufox", "浏览器池已关闭", error_code="camoufox_pool_closed")
        if not self._ready.is_set():
            if not self._ready.wait(timeout=90):
                raise CamoufoxBrowserError(
                    "free_camoufox_launch", "启动 Camoufox 浏览器池",
                    "Camoufox 浏览器池仍在初始化，请稍后重试",
                    retryable=True, error_code="camoufox_pool_init_pending",
                )
        if self._init_error:
            if isinstance(self._init_error, (CamoufoxDependencyError, CamoufoxBrowserError)):
                raise self._init_error
            raise CamoufoxBrowserError(
                "free_camoufox_launch", "启动 Camoufox", "浏览器池初始化失败",
                error_code="camoufox_pool_init_failed",
                diagnostic=_camoufox_error_detail(self._init_error),
            ) from self._init_error
        if self._loop is None:
            raise CamoufoxBrowserError("free_camoufox_launch", "启动 Camoufox", "浏览器事件循环不可用", error_code="camoufox_loop_missing")
        registration_timeout = float(self.config.get("registration_timeout_seconds") or 600)
        cleanup_budget = float(self.config.get("context_close_timeout_seconds") or 15)
        recycle_budget = float(self.config.get("browser_recycle_timeout_seconds") or 45)
        drain_budget = float(self.config.get("browser_recycle_drain_timeout_seconds") or 20)
        controller = kwargs.get("deadline_controller")
        if controller is None:
            supplied_config = kwargs.get("config")
            if isinstance(supplied_config, Mapping):
                controller = supplied_config.get("_deadline_controller")
        if controller is None:
            controller = RegistrationDeadline(registration_timeout)
        effective_kwargs = dict(kwargs)
        effective_config = dict(kwargs.get("config") or {})
        effective_config["_deadline_controller"] = controller
        effective_kwargs["config"] = effective_config
        effective_kwargs["deadline_controller"] = controller
        safety_deadline = time.monotonic() + registration_timeout + max(
            30.0,
            cleanup_budget + recycle_budget + drain_budget
            + (MANUAL_OTP_WINDOW_SECONDS * MAX_MANUAL_OTP_WINDOWS)
            + MANUAL_OTP_POST_SUBMIT_GRACE_SECONDS,
        )
        future = asyncio.run_coroutine_threadsafe(self._register_async(effective_kwargs), self._loop)
        try:
            # The async watchdog observes the pause-aware controller and
            # cancels the registration task when its active budget expires.
            # Keep this cross-thread wait as one bounded operation instead of
            # polling every 250ms: a Future test double (or a scheduler that
            # reports an immediate timeout) must not turn the caller into a
            # hot loop. The allowance covers the three independent broker
            # windows (entry, password and 2FA), post-submit handoff, and
            # context/recycle cleanup.
            wait_budget = max(0.25, safety_deadline - time.monotonic())
            return dict(future.result(timeout=wait_budget))
        except FutureCancelledError as exc:
            # ``run_coroutine_threadsafe`` translates an async
            # ``CancelledError`` into ``concurrent.futures.CancelledError``.
            # Do not let that low-level type escape to FreeRegisterManager's
            # generic exception path; preserve a stable, non-proxy
            # cancellation node for task diagnostics and mailbox safety.
            if self._closed:
                error_code = "camoufox_pool_closed"
                message = "Camoufox 浏览器池已关闭，当前注册被取消"
                source = "pool_shutdown"
            else:
                error_code = "camoufox_registration_cancelled"
                message = "Camoufox 注册任务被取消"
                source = "registration_future"
            failure = CamoufoxBrowserError(
                "free_camoufox_browser", "Camoufox 注册页面", message,
                retryable=False,
                error_code=error_code,
                diagnostic=f"cancellation_source={source}",
            )
            setattr(failure, "safe_restart", False)
            raise failure from exc
        except FutureTimeoutError as exc:
            # The async registration path already bounds page/context cleanup
            # and browser replacement.  Give those operations one final,
            # bounded drain window before cancelling the cross-thread Future;
            # cancelling immediately can interrupt the recycler after it has
            # detached the old browser and leave the caller with no observable
            # completion state.
            try:
                future.result(timeout=max(5.0, min(cleanup_budget + drain_budget + recycle_budget + 5, 30.0)))
            except FutureTimeoutError:
                try:
                    future.cancel()
                except Exception:
                    pass
            except Exception:
                pass
            raise CamoufoxBrowserError("free_camoufox_browser", "Camoufox 注册页面", "浏览器注册超时", error_code="camoufox_registration_timeout") from exc

    def shutdown(self, *, force: bool = False) -> bool:
        completion = getattr(self, "_shutdown_complete", None)
        if completion is None:
            completion = threading.Event()
            self._shutdown_complete = completion
            if getattr(self, "_closed", False) and not getattr(self, "_thread", None):
                completion.set()
        with self._lock:
            if completion.is_set():
                return True
            if not force and (self.has_debug_sessions() or self.has_active_contexts()):
                # Batch completion must leave opted-in diagnostic pages and
                # active task contexts visible. They are closed only after the
                # operator releases the debug session or at process exit.
                return False
            self._closed = True
            shutdown_requested = getattr(self, "_shutdown_requested", None)
            if shutdown_requested is not None:
                shutdown_requested.set()
            loop = self._loop
            if loop is not None:
                try:
                    # Never stop the loop directly. The shutdown coroutine
                    # cancels/drains async work and closes every browser
                    # manager before issuing the final ``loop.stop``.
                    init_finished = getattr(self, "_init_finished", None)
                    if init_finished is None or init_finished.is_set():
                        loop.call_soon_threadsafe(self._schedule_shutdown)
                except (RuntimeError, AttributeError):
                    # The loop may already be in its final close phase. The
                    # completion event below determines whether cleanup really
                    # finished before the pool is removed from the registry.
                    pass
        thread = self._thread
        if thread is None:
            completion.set()
            return True
        if thread is threading.current_thread():
            return completion.is_set()
        thread.join(timeout=_pool_shutdown_wait_budget(self.config))
        if thread.is_alive():
            return False
        completion.set()
        return True


def _proxy_config(proxy: str) -> dict[str, Any] | None:
    config = proxy_transport_config(proxy, driver="camoufox")
    if not config:
        return None
    return {
        key: config[key]
        for key in ("server", "username", "password")
        if config.get(key)
    }


_POOL_LOCK = threading.RLock()
# Registry operations and browser-pool shutdown must share one lifecycle
# barrier.  Without it a settings read or a new task can obtain a pool after
# shutdown has marked it closed but before its event-loop thread has released
# the browser process.
_POOL_LIFECYCLE_LOCK = threading.RLock()
_POOLS: dict[tuple[Any, ...], CamoufoxBrowserPool] = {}


def _pool_timeout(config: Mapping[str, Any], key: str, default: float) -> float:
    """Normalize timeout values used to decide whether a pool is reusable."""
    try:
        value = float(config.get(key) or default)
    except (TypeError, ValueError, OverflowError):
        value = float(default)
    return max(0.001, value)


def _pool_shutdown_wait_budget(config: Mapping[str, Any]) -> float:
    """Bound a synchronous wait for the pool's event-loop thread to exit.

    ``_shutdown_async`` closes browser slots serially.  Each slot can spend
    one browser-recycle timeout in the manager context and one context-close
    timeout in its fallback browser close, so a single-slot budget undercounts
    the real cleanup window as soon as ``pool_size`` is greater than one.  The
    drain timeout and a small handoff margin cover a concurrent recycle that
    was already queued when shutdown started.
    """
    try:
        pool_size = max(1, int(config.get("pool_size") or 2))
    except (TypeError, ValueError, OverflowError):
        pool_size = 2
    context_timeout = _pool_timeout(config, "context_close_timeout_seconds", 15)
    browser_timeout = _pool_timeout(config, "browser_recycle_timeout_seconds", 45)
    drain_timeout = _pool_timeout(
        config, "browser_recycle_drain_timeout_seconds", 20,
    )
    # Slot teardown is currently serial; keep this calculation conservative
    # until that ordering is deliberately changed and covered independently.
    return max(
        5.0,
        (pool_size * (browser_timeout + context_timeout))
        + drain_timeout
        + 10.0,
    )


def _camoufox_pool_key(config: Mapping[str, Any]) -> tuple[Any, ...]:
    """Build the identity used to reuse a compatible browser pool."""
    debug_mode, effective_headless = _effective_camoufox_headless(config)
    # ``_debug_artifact_dir`` is injected only by the runner and is absent
    # from persisted settings read by the public debug-state endpoint. It is
    # an output location, not a browser capability; including it would make
    # the state poller retire the live registration pool as "obsolete".
    return (
        debug_mode, effective_headless, int(config.get("pool_size") or 2),
        int(config.get("max_contexts_per_browser") or 3), bool(config.get("block_images", True)),
        int(config.get("context_start_interval_ms") or 175),
        int(config.get("startup_concurrency") or 4),
        int(config.get("max_registrations_per_browser") or 12),
        int(config.get("browser_launch_attempts") or 3),
        _pool_timeout(config, "registration_timeout_seconds", 600),
        _pool_timeout(config, "context_close_timeout_seconds", 15),
        _pool_timeout(config, "browser_recycle_timeout_seconds", 45),
        _pool_timeout(config, "browser_recycle_drain_timeout_seconds", 20),
    )


def _retire_idle_camoufox_pools_locked(
    *, current_key: tuple[Any, ...] | None = None,
) -> dict[str, int]:
    """Close pools made obsolete by a config change once they are idle.

    A pool with an active task or an operator-held debug context is deliberately
    left registered.  This makes a settings change non-destructive while still
    preventing an idle old browser process from accumulating forever.
    """
    with _POOL_LOCK:
        candidates = list(_POOLS.items())
    closed = 0
    retained = 0
    for key, pool in candidates:
        if current_key is not None and key == current_key:
            continue
        try:
            has_debug = bool(getattr(pool, "has_debug_sessions", lambda: False)())
            has_active = bool(getattr(pool, "has_active_contexts", lambda: False)())
        except Exception:
            retained += 1
            continue
        if has_debug or has_active:
            retained += 1
            continue
        try:
            # ``shutdown`` may still be unwinding its event-loop thread.  A
            # closed pool is no longer a valid admission owner, so detach it
            # now and let that thread finish independently.  Keeping it in the
            # registry caused the next task to inherit a closed/empty pool and
            # surface ``camoufox_pool_shutdown_pending``.
            if bool(getattr(pool, "_closed", False)):
                with _POOL_LOCK:
                    if _POOLS.get(key) is pool:
                        _POOLS.pop(key, None)
                        closed += 1
                continue
            try:
                result = pool.shutdown(force=False)
            except TypeError:
                result = pool.shutdown()
            if result is False:
                retained += 1
                continue
            with _POOL_LOCK:
                if _POOLS.get(key) is pool:
                    _POOLS.pop(key, None)
                    closed += 1
        except Exception:
            retained += 1
    return {"closed_pools": closed, "retained_pools": retained}


def _retire_idle_camoufox_pools(
    *, current_key: tuple[Any, ...] | None = None,
) -> dict[str, int]:
    """Serialize idle-pool retirement with pool lookup and shutdown."""
    with _POOL_LIFECYCLE_LOCK:
        return _retire_idle_camoufox_pools_locked(current_key=current_key)


def _pool_for(config: Mapping[str, Any]) -> CamoufoxBrowserPool:
    key = _camoufox_pool_key(config)
    with _POOL_LIFECYCLE_LOCK:
        # Reconcile pools from a previous settings identity before admitting a
        # new one. Held debug windows and active tasks are retained by design.
        _retire_idle_camoufox_pools_locked(current_key=key)
        # A pool marked closed has already received a shutdown request. Keep
        # its object alive through its own daemon event-loop thread, but remove
        # it from the registry immediately so a new task can obtain a healthy
        # replacement. Waiting here used to surface ``camoufox_pool_shutdown_pending``
        # and caused the next task to race into an empty/disconnected pool.
        with _POOL_LOCK:
            current = _POOLS.get(key)
            if current is not None and not bool(getattr(current, "_closed", False)):
                return current
            if current is not None and _POOLS.get(key) is current:
                _POOLS.pop(key, None)
            for old_key, old_pool in list(_POOLS.items()):
                if old_key != key and bool(getattr(old_pool, "_closed", False)):
                    _POOLS.pop(old_key, None)
            replacement = CamoufoxBrowserPool(config)
            _POOLS[key] = replacement
            return replacement


def _shutdown_camoufox_pools_locked(*, force: bool = False) -> dict[str, int]:
    """Shutdown idle Camoufox pools, preserving opted-in debug sessions.

    ``force=True`` is reserved for process exit. The default keeps active
    tasks and retained debug windows alive during batch completion.
    """
    with _POOL_LOCK:
        pools = list(_POOLS.items())
    closed = 0
    retained = 0
    for key, pool in pools:
        has_debug = bool(getattr(pool, "has_debug_sessions", lambda: False)())
        has_active = bool(getattr(pool, "has_active_contexts", lambda: False)())
        if not force and (has_debug or has_active):
            retained += 1
            continue
        try:
            try:
                result = pool.shutdown(force=force)
            except TypeError:
                # Keep lightweight test doubles and older integration adapters
                # compatible with the no-argument shutdown contract.
                result = pool.shutdown()
            if result is not False:
                closed += 1
                with _POOL_LOCK:
                    if _POOLS.get(key) is pool:
                        _POOLS.pop(key, None)
            else:
                retained += 1
        except Exception:
            retained += 1
    with _POOL_LOCK:
        retained = max(retained, len(_POOLS))
    return {"closed_pools": closed, "retained_pools": retained}


def shutdown_camoufox_pools(*, force: bool = False) -> dict[str, int]:
    """Shutdown pools under the same barrier used by pool lookup."""
    with _POOL_LIFECYCLE_LOCK:
        return _shutdown_camoufox_pools_locked(force=force)


def camoufox_debug_state(config: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Return a secret-free aggregate of retained headed debug contexts.

    Before the first browser pool is created there is no slot object from
    which to derive capacity.  Use the normalized config in that case so the
    public state still reflects the configured debug/headless mode and pool
    capacity instead of briefly reporting a misleading disabled/zero state.
    """
    nested_config = config.get("camoufox") if isinstance(config, Mapping) else None
    # Accept both the public Free config shape and the low-level nested
    # Camoufox mapping used by direct pool callers.  A flat mapping without a
    # ``camoufox`` key must not silently fall back to the default debug mode.
    browser_config = (
        nested_config if isinstance(nested_config, Mapping)
        else (config if isinstance(config, Mapping) else {})
    )
    current_key: tuple[Any, ...] | None = None
    if browser_config:
        try:
            current_key = _camoufox_pool_key(browser_config)
        except (TypeError, ValueError, OverflowError):
            current_key = None
    # Settings can change while no new batch is running. Reap obsolete idle
    # pools during the next state read, while retaining old pools that still
    # own a visible debug window or an active task.
    if current_key is not None:
        _retire_idle_camoufox_pools(current_key=current_key)
    with _POOL_LOCK:
        pool_items = list(_POOLS.items())
    snapshots: list[tuple[tuple[Any, ...], Mapping[str, Any]]] = []
    for key, pool in pool_items:
        getter = getattr(pool, "debug_state", None)
        if not callable(getter):
            continue
        try:
            snapshot = getter()
        except Exception:
            continue
        if isinstance(snapshot, Mapping):
            snapshots.append((key, snapshot))
    snapshot_values = [snapshot for _key, snapshot in snapshots]
    sessions = [item for snapshot in snapshot_values for item in snapshot.get("sessions", [])]
    closing_sessions = sorted({
        str(session_id)
        for snapshot in snapshot_values
        for session_id in (snapshot.get("closing_sessions") or [])
        if str(session_id or "").strip()
    })
    closing_contexts = sum(
        max(0, int(snapshot.get("closing_contexts") or 0))
        for snapshot in snapshot_values
    )
    browser_count = sum(
        max(0, int(snapshot.get("browser_count") or 0))
        for snapshot in snapshot_values
    )
    capacity = sum(max(0, int(snapshot.get("capacity") or 0)) for snapshot in snapshot_values)
    used = sum(max(0, int(snapshot.get("used") or snapshot.get("open_contexts") or 0)) for snapshot in snapshot_values)
    current_snapshot = next(
        (snapshot for key, snapshot in snapshots if current_key is not None and key == current_key),
        None,
    )
    if current_snapshot is not None:
        # ``enabled`` and ``headless`` describe the current settings identity;
        # legacy pools may intentionally have the opposite window mode while
        # their retained pages remain visible to the operator.
        enabled = bool(current_snapshot.get("enabled"))
        headless = bool(current_snapshot.get("headless", True))
    elif snapshot_values:
        # No current pool has been created yet. Use the persisted config for
        # mode flags and keep the legacy pool capacity/occupancy in the totals.
        enabled, headless = _effective_camoufox_headless(browser_config)
    else:
        enabled, headless = _effective_camoufox_headless(browser_config)
        try:
            pool_size = max(1, int(browser_config.get("pool_size") or 2))
            max_contexts = max(1, int(browser_config.get("max_contexts_per_browser") or 3))
            capacity = pool_size * max_contexts
            browser_count = pool_size
        except (TypeError, ValueError):
            capacity = 0
            browser_count = 0
    return {
        "enabled": enabled,
        "headless": headless,
        "capacity": capacity,
        "used": used,
        "available": max(0, capacity - used),
        "open_contexts": len(sessions),
        "closing_contexts": closing_contexts,
        "closing_sessions": closing_sessions,
        "browser_count": browser_count,
        "pool_count": len(snapshots),
        "sessions": sessions,
    }


def annotate_camoufox_debug_session(session_id: str, incident_id: str) -> bool:
    """Best-effort incident association for a retained page."""
    normalized_session = str(session_id or "").strip()
    if not normalized_session:
        return False
    with _POOL_LOCK:
        pools = list(_POOLS.values())
    for pool in pools:
        annotator = getattr(pool, "annotate_debug_session", None)
        if callable(annotator):
            try:
                if annotator(normalized_session, incident_id):
                    return True
            except Exception:
                continue
    return False


def close_camoufox_debug_browsers(
    session_id: str = "",
    *,
    config: Mapping[str, Any] | None = None,
) -> dict[str, int]:
    """Close one/all retained contexts, then safely reap idle pools.

    ``config`` keeps the aggregate state accurate after the last pool is
    removed.  The manager passes the current normalized settings; direct
    compatibility callers can omit it and retain the historical defaults.
    """
    normalized = str(session_id or "").strip()
    with _POOL_LOCK:
        pools = list(_POOLS.values())
    requested = 0
    closed_contexts = 0
    for pool in pools:
        has_debug = bool(getattr(pool, "has_debug_sessions", lambda: False)())
        if has_debug:
            requested += 1
        closer = getattr(pool, "close_debug_sessions", None)
        if callable(closer):
            try:
                closed_contexts += int(closer(normalized))
            except Exception:
                continue
    result = shutdown_camoufox_pools(force=False)
    result["closed_contexts"] = closed_contexts
    remaining = camoufox_debug_state(config)
    result["retained_contexts"] = int(remaining.get("open_contexts") or 0)
    result["remaining_contexts"] = int(remaining.get("open_contexts") or 0)
    result["remaining_sessions"] = int(remaining.get("open_contexts") or 0)
    result["requested_pools"] = requested
    return result


atexit.register(lambda: shutdown_camoufox_pools(force=True))


class CamoufoxRegistrationRunner:
    """Manager-compatible synchronous facade for the async browser pool."""

    def __init__(self, *, lifecycle_store_path: str = "", debug_artifact_dir: str = "") -> None:
        self.lifecycle_store_path = lifecycle_store_path
        self.debug_artifact_dir = debug_artifact_dir or (
            str(Path(lifecycle_store_path).expanduser().resolve().parent / "camoufox_debug")
            if lifecycle_store_path else ""
        )

    @staticmethod
    def preflight(config: Mapping[str, Any]) -> dict[str, Any]:
        _load_camoufox_api()
        runtime_version = _check_camoufox_runtime()
        browser = dict(config.get("camoufox") or {})
        debug_mode, effective_headless = _effective_camoufox_headless(browser)
        return {
            "driver": "camoufox",
            "dependency": "available",
            "runtime_version": runtime_version,
            "debug_mode": debug_mode,
            "headless": effective_headless,
            "pool_size": int(browser.get("pool_size") or 2),
            "max_contexts_per_browser": int(browser.get("max_contexts_per_browser") or 3),
        }

    def __call__(
        self,
        task: Mapping[str, Any],
        config: Mapping[str, Any],
        stop_event: Any,
        stage: Callable[[str, str], None],
        log: Callable[[str, str], None],
        *,
        twofa_retry: bool = False,
        password_retry: bool = False,
    ) -> Mapping[str, Any]:
        if twofa_retry and password_retry:
            raise FreeRegisterError(
                "free_retry", "重试 Free 任务",
                "2FA 重试和密码重试不能同时提交",
                retryable=False, error_code="free_retry_modes_conflict",
            )
        task_id = str(task.get("task_id") or "")
        private_result = task.get("result") if isinstance(task.get("result"), Mapping) else {}
        saved_password_token = str(private_result.get("access_token") or "").strip()
        if password_retry:
            if not saved_password_token:
                raise FreeRegisterError(
                    "free_password_retry", "重试 Free 账号密码设置",
                    "原账号没有可用 access token", retryable=False,
                    error_code="free_password_retry_token_missing",
                )
            if not password_retry_allowed(private_result):
                raise FreeRegisterError(
                    "free_password_retry", "重试 Free 账号密码设置",
                    "该账号当前没有可补设的密码状态", retryable=False,
                    error_code="free_password_retry_not_pending",
                )
        existing_password = ""
        for candidate in (
            private_result.get("password"),
            task.get("password"),
            task.get("saved_password"),
        ):
            if str(candidate or "").strip():
                existing_password = str(candidate).strip()
                break
        if twofa_retry and not existing_password:
            raise FreeRegisterError(
                "free_existing_login", "已有 Free 账号登录",
                "已有账号登录缺少已保存密码，拒绝使用固定注册密码",
                retryable=False, error_code="free_existing_login_password_missing",
            )
        browser_config = dict(config.get("camoufox") or {})
        if self.debug_artifact_dir:
            browser_config["_debug_artifact_dir"] = self.debug_artifact_dir
        deadline_controller = RegistrationDeadline(
            float(browser_config.get("registration_timeout_seconds") or 600)
        )
        task_deadline_controller = deadline_controller
        otp = build_free_mailbox_otp_provider(
            str(task.get("mailbox_url") or ""), str(task.get("proxy") or ""), config,
            log_fn=log, task_id=task_id,
            **({"batch_id": str(task.get("batch_id") or "")} if task.get("batch_id") else {}),
            stage_fn=stage,
        )
        # Keep the builder's historical config identity intact.  The
        # deadline is task-local runtime state, so attach it to the provider
        # instance instead of adding a private key to the caller's mapping.
        try:
            setattr(otp, "deadline_controller", deadline_controller)
        except Exception:
            pass
        try:
            stage(task_id, "free_password_enroll" if password_retry else "free_camoufox_signup")
            if stop_event.is_set():
                raise FreeRegisterError("free_run_stop", "停止 Free 注册", "任务在启动 Camoufox 前已停止", retryable=False)
            def callback(
                stage_code: str = "free_email_otp_wait",
                *,
                stop_requested: Callable[[], bool] | None = None,
                deadline_monotonic: float | None = None,
                deadline_controller: Any | None = None,
            ) -> str:
                active_controller = deadline_controller or task_deadline_controller
                if active_controller is not getattr(otp, "deadline_controller", None):
                    otp.deadline_controller = active_controller
                def combined_stop() -> bool:
                    return stop_event.is_set() or (
                        callable(stop_requested) and bool(stop_requested())
                    )

                return otp.wait_code(
                    str(task.get("email") or ""),
                    stage_code=stage_code,
                    stop_requested=combined_stop,
                    deadline_monotonic=deadline_monotonic,
                )
            result = _pool_for(browser_config).register(
                email=str(task.get("email") or ""),
                # Existing-login and password-continuation adapters retain the
                # historical empty argument shape; _browser_flow resolves the
                # configured value before submitting a signup/password page.
                password="" if (twofa_retry or password_retry) else configured_free_password(config),
                proxy=str(task.get("proxy") or ""), otp_callback=callback,
                otp_prepare=otp.prepare, otp_mark_sent=otp.mark_sent,
                config={
                    **config, **browser_config, "task_id": task_id,
                    "device_id": str(task.get("device_id") or ""),
                    "incident_id": str(task.get("incident_id") or ""),
                    "proxy_fingerprint": str(task.get("proxy_fingerprint") or ""),
                    "_stop_requested": stop_event.is_set,
                    "_deadline_controller": task_deadline_controller,
                }, log=log,
                stage_fn=stage,
                timing_fn=config.get("_timing_substep"),
                force_existing_login=twofa_retry,
                existing_password=existing_password,
                password_retry=password_retry,
                password_retry_token=saved_password_token,
                deadline_controller=task_deadline_controller,
            )
            result = dict(result)
            if password_retry:
                # The browser continuation returns only password fields. Fill
                # missing account evidence from the saved result so a successful
                # password operation cannot erase an existing TOTP/plan/token.
                result = merge_account_result_fields(private_result, result)
            result["registration_ip"] = str(task.get("expected_exit_ip") or task.get("exit_ip") or "")
            result["expected_exit_ip"] = str(task.get("expected_exit_ip") or task.get("exit_ip") or "")
            result["profile_summary"] = "Camoufox shared pool"
            return finalize_registration_result(result, driver="camoufox", email=str(task.get("email") or ""))
        finally:
            close = getattr(otp, "close", None)
            if callable(close):
                try:
                    close()
                except Exception:
                    log("Camoufox 邮箱 OTP 客户端清理失败，不覆盖原任务结果", "warn")


__all__ = [
    "CamoufoxBrowserError", "CamoufoxDependencyError", "CamoufoxRegistrationRunner",
    "CamoufoxBrowserPool", "annotate_camoufox_debug_session", "shutdown_camoufox_pools",
    "browser_add_password",
    # New composable boundaries are lazy compatibility exports; importing
    # them does not initialize a browser or alter the legacy globals.
    "CamoufoxFlowCheckpoint", "CamoufoxFlowContext", "CamoufoxFlowState",
    "CamoufoxPoolSnapshot", "CamoufoxRegistrationRequest",
    "CamoufoxRegistrationResult", "CamoufoxRunner", "CamoufoxStateMachine",
    "CamoufoxFlowCoordinator", "FlowWaitResult",
    "CamoufoxTransport", "CamoufoxTransportError", "DebugArtifactService",
    "DebugEventBuffer", "BrowserPoolGateway", "InvalidTransitionError",
    "PageTransportContract", "StateTransition",
]


def __getattr__(name: str) -> Any:
    """Lazily expose the composable package boundaries from the old entrypoint.

    The live helpers above intentionally remain local: existing tests and
    integrations patch those globals directly.  New code can import the
    smaller contracts/adapters through either ``mac_overrides.free_camoufox``
    or this compatibility module without eagerly importing Camoufox.
    """

    boundary_names = {
        "CamoufoxFlowCheckpoint", "CamoufoxFlowContext", "CamoufoxFlowState",
        "CamoufoxPoolSnapshot", "CamoufoxRegistrationRequest",
        "CamoufoxRegistrationResult", "CamoufoxRunner", "CamoufoxStateMachine",
        "CamoufoxFlowCoordinator", "FlowWaitResult",
        "CamoufoxTransport", "CamoufoxTransportError", "DebugArtifactService",
        "DebugEventBuffer", "BrowserPoolGateway", "InvalidTransitionError",
        "PageTransportContract", "StateTransition",
    }
    if name not in boundary_names:
        raise AttributeError(name)
    try:
        from . import free_camoufox as boundaries
    except ImportError:  # pragma: no cover - top-level recovery import
        import free_camoufox as boundaries  # type: ignore
    return getattr(boundaries, name)
