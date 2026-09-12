"""Optional Camoufox browser driver for the Free registration workflow.

Camoufox is deliberately imported lazily so the protocol driver remains usable
when the optional browser package is absent.
The browser pool owns only browser/context lifecycle; mailbox, result and
failure semantics stay in the Free runtime and shared account service.
"""

from __future__ import annotations

import sys

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


# ---------------------------------------------------------------------------
# Pure support tables and helpers live in the free_camoufox package now:
#   selectors.py       page selector tuples / auth-state sets
#   deadline.py        RegistrationDeadline + manual-OTP budget constants
#   errors.py          browser-loss / transient-navigation classification
#   debug_redaction.py credential-safe debug text sanitization
#   url_safety.py      bounded URL / incident-id / task-id / fingerprint views
# The names below keep their historical module-level bindings so tests and
# compatibility adapters can keep patching ``free_camoufox_runtime.<name>``.
try:
    from .free_camoufox.selectors import (  # noqa: E402
        CHATGPT_LOGIN_URL,
        EMAIL_SELECTORS,
        OTP_SELECTORS,
        PASSWORD_SELECTORS,
        LOGIN_PASSWORD_SELECTORS,
        NAME_SELECTORS,
        BIRTHDAY_SELECTORS,
        AGE_SELECTORS,
        EMAIL_SUBMIT_SELECTORS,
        PASSWORD_SUBMIT_SELECTORS,
        PASSWORDLESS_SELECTORS,
        LOGIN_PASSWORD_SUBMIT_SELECTORS,
        RESEND_SELECTORS,
        PROFILE_SUBMIT_SELECTORS,
        _POST_ENTRY_AUTH_STATES,
    )
    from .free_camoufox.deadline import (  # noqa: E402
        MANUAL_OTP_HANDOFF_GRACE_SECONDS,
        MANUAL_OTP_POST_SUBMIT_GRACE_SECONDS,
        MANUAL_OTP_WINDOW_SECONDS,
        MAX_MANUAL_OTP_WINDOWS,
        RegistrationDeadline,
        deadline_controller_bool as _deadline_controller_bool_impl,
        deadline_controller_call as _deadline_controller_call_impl,
        profile_transition_timing_outcome as _profile_transition_timing_outcome_impl,
    )
    from .free_camoufox.errors import (  # noqa: E402
        PROXY_BLOCK_PAGE_MARKERS as _PROXY_BLOCK_PAGE_MARKERS,
        browser_process_lost as _browser_process_lost_impl,
        is_transient_navigation_error as _is_transient_navigation_error_impl,
        mark_recycle_required as _mark_recycle_required_impl,
        navigation_diagnostic as _navigation_diagnostic_impl,
        navigation_failure_category as _navigation_failure_category_impl,
        navigation_failure_reason as _navigation_failure_reason_impl,
    )
    from .free_camoufox.debug_redaction import (  # noqa: E402
        debug_alnum_is_safe_identifier as _debug_alnum_is_safe_identifier,
        debug_body_has_sensitive_token as _debug_body_has_sensitive_token,
        debug_grouped_is_candidate as _debug_grouped_is_candidate,
        debug_grouped_secret_start as _debug_grouped_secret_start,
        debug_otp_context as _debug_otp_context,
        safe_body_markers as _safe_body_markers_impl,
        sanitize_debug_text as _sanitize_debug_text_impl,
        _SCREENSHOT_SCAN_LIMIT,
    )
    from .free_camoufox.url_safety import (  # noqa: E402
        safe_debug_task_id as _safe_debug_task_id_impl,
        safe_event_url as _safe_event_url_impl,
        safe_incident_id as _safe_incident_id_impl,
        safe_proxy_fingerprint as _safe_proxy_fingerprint_impl,
        safe_url as _safe_url_impl,
    )
except ImportError:  # pragma: no cover - top-level recovery import
    from free_camoufox.selectors import (  # type: ignore[no-redef]
        CHATGPT_LOGIN_URL,
        EMAIL_SELECTORS,
        OTP_SELECTORS,
        PASSWORD_SELECTORS,
        LOGIN_PASSWORD_SELECTORS,
        NAME_SELECTORS,
        BIRTHDAY_SELECTORS,
        AGE_SELECTORS,
        EMAIL_SUBMIT_SELECTORS,
        PASSWORD_SUBMIT_SELECTORS,
        PASSWORDLESS_SELECTORS,
        LOGIN_PASSWORD_SUBMIT_SELECTORS,
        RESEND_SELECTORS,
        PROFILE_SUBMIT_SELECTORS,
        _POST_ENTRY_AUTH_STATES,
    )
    from free_camoufox.deadline import (  # type: ignore[no-redef]
        MANUAL_OTP_HANDOFF_GRACE_SECONDS,
        MANUAL_OTP_POST_SUBMIT_GRACE_SECONDS,
        MANUAL_OTP_WINDOW_SECONDS,
        MAX_MANUAL_OTP_WINDOWS,
        RegistrationDeadline,
        deadline_controller_bool as _deadline_controller_bool_impl,
        deadline_controller_call as _deadline_controller_call_impl,
        profile_transition_timing_outcome as _profile_transition_timing_outcome_impl,
    )
    from free_camoufox.errors import (  # type: ignore[no-redef]
        PROXY_BLOCK_PAGE_MARKERS as _PROXY_BLOCK_PAGE_MARKERS,
        browser_process_lost as _browser_process_lost_impl,
        is_transient_navigation_error as _is_transient_navigation_error_impl,
        mark_recycle_required as _mark_recycle_required_impl,
        navigation_diagnostic as _navigation_diagnostic_impl,
        navigation_failure_category as _navigation_failure_category_impl,
        navigation_failure_reason as _navigation_failure_reason_impl,
    )
    from free_camoufox.debug_redaction import (  # type: ignore[no-redef]
        debug_alnum_is_safe_identifier as _debug_alnum_is_safe_identifier,
        debug_body_has_sensitive_token as _debug_body_has_sensitive_token,
        debug_grouped_is_candidate as _debug_grouped_is_candidate,
        debug_grouped_secret_start as _debug_grouped_secret_start,
        debug_otp_context as _debug_otp_context,
        safe_body_markers as _safe_body_markers_impl,
        sanitize_debug_text as _sanitize_debug_text_impl,
        _SCREENSHOT_SCAN_LIMIT,
    )
    from free_camoufox.url_safety import (  # type: ignore[no-redef]
        safe_debug_task_id as _safe_debug_task_id_impl,
        safe_event_url as _safe_event_url_impl,
        safe_incident_id as _safe_incident_id_impl,
        safe_proxy_fingerprint as _safe_proxy_fingerprint_impl,
        safe_url as _safe_url_impl,
    )


class CamoufoxBrowserError(FreeRegisterError):
    pass


def _profile_transition_timing_outcome(state: str) -> str:
    """Delegate to the shared deadline helper; see its docstring for semantics."""
    return _profile_transition_timing_outcome_impl(state)


_DEADLINE_CONTROLLER_MISSING = object()


def _deadline_controller_call(
    controller: Any,
    name: str,
    *args: Any,
    default: Any = _DEADLINE_CONTROLLER_MISSING,
) -> Any:
    """Invoke an optional controller hook without making it a failure node."""
    return _deadline_controller_call_impl(controller, name, *args, default=default)


def _deadline_controller_bool(controller: Any, name: str) -> bool:
    return _deadline_controller_bool_impl(controller, name)


# Name used by a few recovered integrations and focused tests.
_RegistrationDeadlineController = RegistrationDeadline


def _browser_process_lost(exc: BaseException) -> bool:
    return _browser_process_lost_impl(exc)


def _is_transient_navigation_error(exc: BaseException) -> bool:
    return _is_transient_navigation_error_impl(exc)


def _navigation_failure_category(exc: BaseException) -> str:
    return _navigation_failure_category_impl(exc)


def _navigation_failure_reason(exc: BaseException) -> str:
    return _navigation_failure_reason_impl(exc)


def _navigation_diagnostic(exc: BaseException, page: Any) -> str:
    """Return a small, stable diagnostic without persisting exception text."""
    category = _navigation_failure_category(exc)
    exception_type = type(exc).__name__[:80] or "UnknownError"
    safe_page = _safe_url(page)
    reason = _navigation_failure_reason(exc)
    reason_field = f"; reason={reason}" if reason else ""
    return f"category={category}; exception_type={exception_type}{reason_field}; safe_page={safe_page}"


def _mark_recycle_required(error: BaseException, reason: str = "") -> BaseException:
    return _mark_recycle_required_impl(error, reason)


class CamoufoxDependencyError(FreeRegisterError):
    def __init__(self, detail: str = "") -> None:
        super().__init__(
            "free_camoufox_dependency", "检查 Camoufox 依赖",
            "Camoufox 未安装或运行时不可用" + (f"（{clean(detail, 180)}）" if detail else ""),
            retryable=False,
            error_code="camoufox_dependency_missing",
            action_hint="安装 camoufox 及其浏览器运行时后重新执行 Free 预检",
        )


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


def _host_module():
    """Return this module by name so split-out callables stay late-bound.

    Resolving via :data:`sys.modules` keeps the delegated callables reading
    the live ``free_camoufox_runtime`` globals exactly as the original inline
    implementations did, including test patches of helper names.
    """
    import sys
    module = sys.modules.get(__name__)
    if module is not None:
        return module
    # Top-level recovery loads can race the package-qualified import; fall
    # back to the registered qualified name before giving up.
    return sys.modules.get("mac_overrides.free_camoufox_runtime", sys.modules.get("free_camoufox_runtime"))


try:
    from . import free_camoufox as _camoufox_pkg
except ImportError:  # pragma: no cover - top-level recovery import
    import free_camoufox as _camoufox_pkg  # type: ignore[no-redef]
_camoufox_page = _camoufox_pkg.page_interactions
_camoufox_flow = _camoufox_pkg.browser_flow
_camoufox_registry = _camoufox_pkg.browser_registry
for _split_mod in (_camoufox_page, _camoufox_flow, _camoufox_registry):
    if hasattr(_split_mod, "_host_module_ref"):
        _split_mod._host_module_ref = sys.modules[__name__]


# Mutable registries stay on the hosting runtime module; the split-out
# page/flow/registry callables reach them through the late-bound host.
_ARTIFACT_LOCK = threading.RLock()
_ARTIFACT_PROTECTED_SESSIONS: set[str] = set()
_ARTIFACT_SESSION_RE = re.compile(r"^cam-debug-[0-9a-f]{12}$")

_POOL_LOCK = threading.RLock()
# Registry operations and browser-pool shutdown must share one lifecycle
# barrier.  Without it a settings read or a new task can obtain a pool after
# shutdown has marked it closed but before its event-loop thread has released
# the browser process.
_POOL_LIFECYCLE_LOCK = threading.RLock()
_POOLS: dict[tuple[Any, ...], CamoufoxBrowserPool] = {}


def _camoufox_error_detail(
    exc,
) -> str:
    return _camoufox_page._camoufox_error_detail(
        _host_module(),
        exc=exc,
    )

def _context_failure_diagnostic(
    exc,
) -> str:
    return _camoufox_page._context_failure_diagnostic(
        _host_module(),
        exc=exc,
    )

def _safe_url(
    page,
) -> str:
    return _camoufox_page._safe_url(
        _host_module(),
        page=page,
    )

def _safe_event_url(
    value,
) -> str:
    return _camoufox_page._safe_event_url(
        _host_module(),
        value=value,
    )

def _safe_incident_id(
    value,
) -> str:
    return _camoufox_page._safe_incident_id(
        _host_module(),
        value=value,
    )

def _safe_debug_task_id(
    value,
) -> str:
    return _camoufox_page._safe_debug_task_id(
        _host_module(),
        value=value,
    )

def _safe_proxy_fingerprint(
    provided,
    proxy='',
) -> str:
    return _camoufox_page._safe_proxy_fingerprint(
        _host_module(),
        provided=provided,
        proxy=proxy,
    )

def _sanitize_debug_text(
    value,
    limit=800,
    *,
    mask_bare_numeric=True,
) -> str:
    return _camoufox_page._sanitize_debug_text(
        _host_module(),
        value=value,
        limit=limit,
        mask_bare_numeric=mask_bare_numeric,
    )

def _runtime_bool(
    value,
    default=False,
) -> bool:
    return _camoufox_page._runtime_bool(
        _host_module(),
        value=value,
        default=default,
    )

def _effective_camoufox_headless(
    config,
) -> tuple[bool, bool]:
    return _camoufox_page._effective_camoufox_headless(
        _host_module(),
        config=config,
    )

def _safe_body_markers(
    value,
) -> list[str]:
    return _camoufox_page._safe_body_markers(
        _host_module(),
        value=value,
    )

async def _body_text(
    page,
) -> str:
    return await _camoufox_page._body_text(
        _host_module(),
        page=page,
    )

async def _snapshot(
    page,
) -> dict[str, Any]:
    return await _camoufox_page._snapshot(
        _host_module(),
        page=page,
    )

async def _screenshot_safety_check(
    page,
) -> tuple[bool, str]:
    return await _camoufox_page._screenshot_safety_check(
        _host_module(),
        page=page,
    )

def _page_debug_trace(
    page,
) -> host._DebugTrace:
    return _camoufox_page._page_debug_trace(
        _host_module(),
        page=page,
    )

async def _capture_debug_dom(
    page,
) -> dict[str, Any]:
    return await _camoufox_page._capture_debug_dom(
        _host_module(),
        page=page,
    )

def _atomic_artifact_write(
    path,
    payload,
) -> None:
    return _camoufox_page._atomic_artifact_write(
        _host_module(),
        path=path,
        payload=payload,
    )

def _trim_debug_artifacts(
    artifact_root,
    *,
    current_session='',
) -> None:
    return _camoufox_page._trim_debug_artifacts(
        _host_module(),
        artifact_root=artifact_root,
        current_session=current_session,
    )

async def _capture_debug_artifact(
    *,
    page,
    artifact_root,
    session_id,
    artifact_id,
    summary,
    trace,
) -> dict[str, Any]:
    return await _camoufox_page._capture_debug_artifact(
        _host_module(),
        page=page,
        artifact_root=artifact_root,
        session_id=session_id,
        artifact_id=artifact_id,
        summary=summary,
        trace=trace,
    )

async def _close_context_safely(
    context,
    timeout,
) -> bool:
    return await _camoufox_page._close_context_safely(
        _host_module(),
        context=context,
        timeout=timeout,
    )

async def _close_async_resource(
    close_fn,
    timeout,
) -> bool:
    return await _camoufox_page._close_async_resource(
        _host_module(),
        close_fn=close_fn,
        timeout=timeout,
    )

async def _page_visible_text(
    page,
) -> str:
    return await _camoufox_page._page_visible_text(
        _host_module(),
        page=page,
    )

async def _hard_proxy_block_reason(
    page,
) -> str:
    return await _camoufox_page._hard_proxy_block_reason(
        _host_module(),
        page=page,
    )

async def _is_cloudflare_challenge(
    page,
) -> bool:
    return await _camoufox_page._is_cloudflare_challenge(
        _host_module(),
        page=page,
    )

async def _wait_challenge_then_stop(
    page,
    *,
    timeout=30.0,
) -> None:
    return await _camoufox_page._wait_challenge_then_stop(
        _host_module(),
        page=page,
        timeout=timeout,
    )

async def _wait_for_any_selector(
    page,
    selectors,
    *,
    timeout=30.0,
) -> str | None:
    return await _camoufox_page._wait_for_any_selector(
        _host_module(),
        page=page,
        selectors=selectors,
        timeout=timeout,
    )

async def _wait_for_entry_hydration(
    page,
    *,
    timeout=1.5,
) -> None:
    return await _camoufox_page._wait_for_entry_hydration(
        _host_module(),
        page=page,
        timeout=timeout,
    )

async def _find_visible_selector(
    page,
    selectors,
) -> str | None:
    return await _camoufox_page._find_visible_selector(
        _host_module(),
        page=page,
        selectors=selectors,
    )

async def _fill_input_like_user(
    page,
    selector,
    value,
    *,
    click=True,
) -> bool:
    return await _camoufox_page._fill_input_like_user(
        _host_module(),
        page=page,
        selector=selector,
        value=value,
        click=click,
    )

async def _submit_email_form_stable(
    page,
    email,
) -> dict[str, Any]:
    return await _camoufox_page._submit_email_form_stable(
        _host_module(),
        page=page,
        email=email,
    )

async def _click_first(
    page,
    selectors,
    *,
    timeout=8.0,
) -> str | None:
    return await _camoufox_page._click_first(
        _host_module(),
        page=page,
        selectors=selectors,
        timeout=timeout,
    )

async def _click_exact_button_text(
    page,
    texts,
    *,
    timeout=8.0,
) -> str | None:
    return await _camoufox_page._click_exact_button_text(
        _host_module(),
        page=page,
        texts=texts,
        timeout=timeout,
    )

async def _wait_for_submit_enabled(
    page,
    selectors,
    *,
    timeout=20.0,
) -> str | None:
    return await _camoufox_page._wait_for_submit_enabled(
        _host_module(),
        page=page,
        selectors=selectors,
        timeout=timeout,
    )

async def _submit_visible_form(
    page,
    selector,
) -> bool | None:
    return await _camoufox_page._submit_visible_form(
        _host_module(),
        page=page,
        selector=selector,
    )

async def _click_visible_submit(
    page,
    selector,
) -> bool | None:
    return await _camoufox_page._click_visible_submit(
        _host_module(),
        page=page,
        selector=selector,
    )

def _record_email_submit_action_failure(
    page,
    action,
    exc,
) -> None:
    return _camoufox_page._record_email_submit_action_failure(
        _host_module(),
        page=page,
        action=action,
        exc=exc,
    )

async def _email_submit_uncertain_diagnostic(
    page,
    *,
    reason,
    form_present,
    input_selector='',
    submit_selector='',
) -> str:
    return await _camoufox_page._email_submit_uncertain_diagnostic(
        _host_module(),
        page=page,
        reason=reason,
        form_present=form_present,
        input_selector=input_selector,
        submit_selector=submit_selector,
    )

async def _auth_error_text(
    page,
) -> str:
    return await _camoufox_page._auth_error_text(
        _host_module(),
        page=page,
    )

async def _accept_about_you_consents(
    page,
    log,
) -> bool:
    return await _camoufox_page._accept_about_you_consents(
        _host_module(),
        page=page,
        log=log,
    )

async def _confirm_birthday(
    page,
    log,
    *,
    timeout=1.0,
) -> bool:
    return await _camoufox_page._confirm_birthday(
        _host_module(),
        page=page,
        log=log,
        timeout=timeout,
    )

async def _goto_with_retry(
    page,
    url,
    *,
    timeout_ms,
    proxy_retryable,
    attempts=1,
    log=None,
    accept_usable_entry=True,
) -> Any:
    return await _camoufox_page._goto_with_retry(
        _host_module(),
        page=page,
        url=url,
        timeout_ms=timeout_ms,
        proxy_retryable=proxy_retryable,
        attempts=attempts,
        log=log,
        accept_usable_entry=accept_usable_entry,
    )

def _is_navigation_timeout_failure(
    error,
) -> bool:
    return _camoufox_page._is_navigation_timeout_failure(
        _host_module(),
        error=error,
    )

async def _wait_for_post_entry_auth_state(
    page,
    *,
    timeout=5.0,
    poll_interval=0.25,
) -> str:
    return await _camoufox_page._wait_for_post_entry_auth_state(
        _host_module(),
        page=page,
        timeout=timeout,
        poll_interval=poll_interval,
    )

async def _response_retry_after(
    response,
) -> int:
    return await _camoufox_page._response_retry_after(
        _host_module(),
        response=response,
    )

async def _goto_with_diagnostics(
    page,
    url,
    *,
    timeout_ms,
    proxy_retryable=False,
    wrap_errors=True,
) -> Any:
    return await _camoufox_page._goto_with_diagnostics(
        _host_module(),
        page=page,
        url=url,
        timeout_ms=timeout_ms,
        proxy_retryable=proxy_retryable,
        wrap_errors=wrap_errors,
    )

async def _new_context(
    browser,
    *,
    proxy,
) -> Any:
    return await _camoufox_page._new_context(
        _host_module(),
        browser=browser,
        proxy=proxy,
    )

async def _visible(
    page,
    selectors,
    timeout=500,
) -> Any | None:
    return await _camoufox_page._visible(
        _host_module(),
        page=page,
        selectors=selectors,
        timeout=timeout,
    )

async def _fill(
    locator,
    value,
) -> bool:
    return await _camoufox_page._fill(
        _host_module(),
        locator=locator,
        value=value,
    )

async def _click(
    page,
    selectors,
    timeout=2500,
) -> bool:
    return await _camoufox_page._click(
        _host_module(),
        page=page,
        selectors=selectors,
        timeout=timeout,
    )

async def _submit(
    locator,
) -> bool:
    return await _camoufox_page._submit(
        _host_module(),
        locator=locator,
    )

async def _browser_signin_url(
    page,
    email,
) -> str:
    return await _camoufox_page._browser_signin_url(
        _host_module(),
        page=page,
        email=email,
    )

def _is_chatgpt_entry_url(
    value,
) -> bool:
    return _camoufox_page._is_chatgpt_entry_url(
        _host_module(),
        value=value,
    )

async def _page_state(
    page,
) -> str:
    return await _camoufox_page._page_state(
        _host_module(),
        page=page,
    )

async def _wait_state(
    page,
    timeout,
    *states,
) -> str:
    return await _camoufox_page._wait_state(
        _host_module(),
        page=page,
        timeout=timeout,
        *states,
    )

async def _accept_consents(
    page,
) -> None:
    return await _camoufox_page._accept_consents(
        _host_module(),
        page=page,
    )

async def _sync_hidden_birthday_input(
    page,
    birthdate,
) -> bool:
    return await _camoufox_page._sync_hidden_birthday_input(
        _host_module(),
        page=page,
        birthdate=birthdate,
    )

def _reference_age_and_birthdate() -> tuple[int, str]:
    return _camoufox_page._reference_age_and_birthdate(_host_module())

async def _submit_existing_login_password(
    page,
    password,
) -> bool:
    return await _camoufox_page._submit_existing_login_password(
        _host_module(),
        page=page,
        password=password,
    )

async def _click_passwordless_login_switch(
    page,
) -> bool:
    return await _camoufox_page._click_passwordless_login_switch(
        _host_module(),
        page=page,
    )

def _login_totp_code(
    secret,
) -> str:
    return _camoufox_page._login_totp_code(secret)

async def _submit_existing_login_totp(
    page,
    code,
) -> bool:
    return await _camoufox_page._submit_existing_login_totp(
        _host_module(),
        page=page,
        code=code,
    )

def _stop_requested(
    value,
) -> bool:
    return _camoufox_page._stop_requested(
        _host_module(),
        value=value,
    )

def _invoke_otp_callback(
    callback,
    stage_code,
    *,
    stop_requested,
    deadline_monotonic,
    deadline_controller=None,
) -> Any:
    return _camoufox_page._invoke_otp_callback(
        _host_module(),
        callback=callback,
        stage_code=stage_code,
        stop_requested=stop_requested,
        deadline_monotonic=deadline_monotonic,
        deadline_controller=deadline_controller,
    )

def _invoke_mailbox_lease_callback(
    callback,
    *,
    task_id,
    email,
    driver='camoufox',
    stage='free_camoufox_signup_email',
    submission_definitely_not_started=None,
) -> Any:
    return _camoufox_page._invoke_mailbox_lease_callback(
        _host_module(),
        callback=callback,
        task_id=task_id,
        email=email,
        driver=driver,
        stage=stage,
        submission_definitely_not_started=submission_definitely_not_started,
    )

async def _await_otp_callback(
    callback,
    stage_code,
    *,
    deadline_monotonic,
    stop_requested=None,
    deadline_controller=None,
) -> Any:
    return await _camoufox_page._await_otp_callback(
        _host_module(),
        callback=callback,
        stage_code=stage_code,
        deadline_monotonic=deadline_monotonic,
        stop_requested=stop_requested,
        deadline_controller=deadline_controller,
    )

async def _browser_flow(
    page,
    *,
    email,
    password,
    proxy='',
    otp_callback,
    config,
    log,
    otp_prepare=None,
    otp_mark_sent=None,
    stage_fn=None,
    timing_fn=None,
    force_existing_login=False,
    existing_password='',
    existing_totp_secret='',
    plan_recheck=False,
    password_retry=False,
    password_retry_token='',
    startup_gate=None,
    deadline_controller=None,
) -> dict[str, Any]:
    return await _camoufox_flow._browser_flow(
        _host_module(),
        page=page,
        email=email,
        password=password,
        proxy=proxy,
        otp_callback=otp_callback,
        config=config,
        log=log,
        otp_prepare=otp_prepare,
        otp_mark_sent=otp_mark_sent,
        stage_fn=stage_fn,
        timing_fn=timing_fn,
        force_existing_login=force_existing_login,
        existing_password=existing_password,
        existing_totp_secret=existing_totp_secret,
        plan_recheck=plan_recheck,
        password_retry=password_retry,
        password_retry_token=password_retry_token,
        startup_gate=startup_gate,
        deadline_controller=deadline_controller,
    )

async def _finish_plan_recheck_flow(
    page,
    *,
    email,
    password,
    config,
    controller,
    deadline_fn,
    login_password_submitted,
    saved_password_status,
    saved_twofa_status,
    saved_has_totp,
    otp_callback,
    otp_prepare=None,
    otp_mark_sent=None,
    timing_fn=None,
    set_stage,
) -> dict[str, Any]:
    return await _camoufox_flow._finish_plan_recheck_flow(
        _host_module(),
        page=page,
        email=email,
        password=password,
        config=config,
        controller=controller,
        deadline_fn=deadline_fn,
        login_password_submitted=login_password_submitted,
        saved_password_status=saved_password_status,
        saved_twofa_status=saved_twofa_status,
        saved_has_totp=saved_has_totp,
        otp_callback=otp_callback,
        otp_prepare=otp_prepare,
        otp_mark_sent=otp_mark_sent,
        timing_fn=timing_fn,
        set_stage=set_stage,
    )

def _proxy_config(
    proxy,
) -> dict[str, Any] | None:
    return _camoufox_registry._proxy_config(
        _host_module(),
        proxy=proxy,
    )

def _pool_timeout(
    config,
    key,
    default,
) -> float:
    return _camoufox_registry._pool_timeout(
        _host_module(),
        config=config,
        key=key,
        default=default,
    )

def _pool_shutdown_wait_budget(
    config,
) -> float:
    return _camoufox_registry._pool_shutdown_wait_budget(
        _host_module(),
        config=config,
    )

def _camoufox_pool_key(
    config,
) -> tuple[Any, ...]:
    return _camoufox_registry._camoufox_pool_key(
        _host_module(),
        config=config,
    )

def _retire_idle_camoufox_pools_locked(
    *,
    current_key=None,
) -> dict[str, int]:
    return _camoufox_registry._retire_idle_camoufox_pools_locked(
        _host_module(),
        current_key=current_key,
    )

def _retire_idle_camoufox_pools(
    *,
    current_key=None,
) -> dict[str, int]:
    return _camoufox_registry._retire_idle_camoufox_pools(
        _host_module(),
        current_key=current_key,
    )

def _pool_for(
    config,
) -> host.CamoufoxBrowserPool:
    return _camoufox_registry._pool_for(
        _host_module(),
        config=config,
    )

def _shutdown_camoufox_pools_locked(
    *,
    force=False,
) -> dict[str, int]:
    return _camoufox_registry._shutdown_camoufox_pools_locked(
        _host_module(),
        force=force,
    )

def shutdown_camoufox_pools(
    *,
    force=False,
) -> dict[str, int]:
    return _camoufox_registry.shutdown_camoufox_pools(
        _host_module(),
        force=force,
    )

def _force_close_idle_camoufox_pools() -> dict[str, int]:
    return _camoufox_registry._force_close_idle_camoufox_pools(_host_module())

def camoufox_debug_state(
    config=None,
) -> dict[str, Any]:
    return _camoufox_registry.camoufox_debug_state(
        _host_module(),
        config=config,
    )

def annotate_camoufox_debug_session(
    session_id,
    incident_id,
) -> bool:
    return _camoufox_registry.annotate_camoufox_debug_session(
        _host_module(),
        session_id=session_id,
        incident_id=incident_id,
    )

def close_camoufox_debug_browsers(
    session_id='',
    *,
    config=None,
) -> dict[str, int]:
    return _camoufox_registry.close_camoufox_debug_browsers(
        _host_module(),
        session_id=session_id,
        config=config,
    )


# Class aliases: one object identity across the runtime facade and the
# split-out modules so isinstance checks and patch targets keep working.
try:
    from .free_camoufox.page_interactions import _DebugTrace  # noqa: E402
    from .free_camoufox.browser_registry import (  # noqa: E402
        _BrowserSlot,
        _DebugSession,
        _HeldSemaphore,
        _SlotAdmissionRace,
        CamoufoxBrowserPool,
        CamoufoxRegistrationRunner,
    )
except ImportError:  # pragma: no cover - top-level recovery import
    from free_camoufox.page_interactions import _DebugTrace  # type: ignore[no-redef]
    from free_camoufox.browser_registry import (  # type: ignore[no-redef]
        _BrowserSlot,
        _DebugSession,
        _HeldSemaphore,
        _SlotAdmissionRace,
        CamoufoxBrowserPool,
        CamoufoxRegistrationRunner,
    )

atexit.register(lambda: shutdown_camoufox_pools(force=True))


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
