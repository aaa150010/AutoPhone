"""Bounded page-interaction helpers for the Camoufox Free flow.

Split out of ``free_camoufox_runtime``; every callable receives the hosting
runtime module as its first ``host`` argument so tests and integrations can
keep patching ``free_camoufox_runtime.<name>`` globals with unchanged
semantics.
"""

from __future__ import annotations

_host_module_ref = None



try:
    from ..quiet_note import note_stderr
except ImportError:  # pragma: no cover - top-level recovery import
    from quiet_note import note_stderr  # type: ignore[no-redef]

def _note_stderr(where: str, exc: BaseException) -> None:
    note_stderr('page_interactions', where, exc)


def _host_mod():
    """Return the hosting runtime module (bound at import time)."""
    return _host_module_ref

import asyncio
from datetime import date
import inspect
import json
import math
import os
import random
import re
import shutil
import threading
import time
import traceback
import uuid
from collections import deque
from pathlib import Path
from typing import Any, Callable, Deque, Mapping
from urllib.parse import urlencode, urlsplit


try:
    from .selectors import (
        BIRTHDAY_SELECTORS,
        EMAIL_SELECTORS,
        LOGIN_PASSWORD_SELECTORS,
        LOGIN_PASSWORD_SUBMIT_SELECTORS,
        NAME_SELECTORS,
        OTP_SELECTORS,
        PASSWORDLESS_SELECTORS,
        PASSWORD_SELECTORS,
    )
except ImportError:  # pragma: no cover - top-level recovery import
    from free_camoufox.selectors import (  # type: ignore[no-redef]
        BIRTHDAY_SELECTORS,
        EMAIL_SELECTORS,
        LOGIN_PASSWORD_SELECTORS,
        LOGIN_PASSWORD_SUBMIT_SELECTORS,
        NAME_SELECTORS,
        OTP_SELECTORS,
        PASSWORDLESS_SELECTORS,
        PASSWORD_SELECTORS,
    )

try:
    from .deadline import MANUAL_OTP_HANDOFF_GRACE_SECONDS
except ImportError:  # pragma: no cover - top-level recovery import
    from free_camoufox.deadline import MANUAL_OTP_HANDOFF_GRACE_SECONDS  # type: ignore[no-redef]

try:
    from ..free_register_common import FreeRegisterError, clean
except ImportError:  # pragma: no cover - top-level recovery import
    from free_register_common import FreeRegisterError, clean  # type: ignore[no-redef]




def _camoufox_error_detail(host, exc: BaseException) -> str:
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


def _context_failure_diagnostic(host, exc: BaseException) -> str:
    """Return a stable, credential-free reason for context startup failures."""
    text = (str(exc or "") or str(getattr(exc, "message", "") or "")).casefold()
    if host._browser_process_lost(exc):
        reason = "browser_process_lost"
    elif any(marker in text for marker in ("proxy", "socks", "connect", "connection", "timed out", "timeout")):
        reason = "proxy_or_transport"
    elif any(marker in text for marker in ("permission", "denied", "executable", "binary")):
        reason = "browser_runtime"
    else:
        reason = "context_api_error"
    return f"exception_type={type(exc).__name__[:80] or 'UnknownError'}; reason={reason}"


def _safe_url(host, page: Any) -> str:
    return host._safe_url_impl(page)


def _safe_event_url(host, value: Any) -> str:
    return host._safe_event_url_impl(value)


def _safe_incident_id(host, value: Any) -> str:
    return host._safe_incident_id_impl(value)


def _safe_debug_task_id(host, value: Any) -> str:
    return host._safe_debug_task_id_impl(value)


def _safe_proxy_fingerprint(host, provided: Any, proxy: Any = "") -> str:
    return host._safe_proxy_fingerprint_impl(provided, proxy)


def _sanitize_debug_text(host, value: Any, limit: int = 800, *, mask_bare_numeric: bool = True) -> str:
    return host._sanitize_debug_text_impl(value, limit, mask_bare_numeric=mask_bare_numeric)


def _runtime_bool(host, value: Any, default: bool = False) -> bool:
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


def _effective_camoufox_headless(host, config: Mapping[str, Any] | None) -> tuple[bool, bool]:
    """Return ``(debug_enabled, effective_headless)`` for a browser config."""
    values = config if isinstance(config, Mapping) else {}
    # Public callers commonly pass the full Free config while low-level pool
    # callers pass the nested ``camoufox`` section.  Normalize both shapes at
    # this boundary so a direct compatibility call cannot silently re-enable
    # the wrong window mode.
    nested = values.get("camoufox")
    if isinstance(nested, Mapping):
        values = nested
    debug_mode = host._runtime_bool(values.get("debug_mode"), True)
    persisted_headless = host._runtime_bool(values.get("headless"), True)
    return debug_mode, (False if debug_mode else persisted_headless)


def _safe_body_markers(host, value: Any) -> list[str]:
    return host._safe_body_markers_impl(value)


async def _body_text(host, page: Any) -> str:
    try:
        return host.clean(await page.locator("body").inner_text(timeout=1500), 1800)
    except Exception:
        return ""


async def _snapshot(host, page: Any) -> dict[str, Any]:
    body = await host._body_text(page)
    try:
        title = host.clean(await page.title(), 160)
    except Exception:
        title = ""
    return {"url": host._safe_url(page), "title": title, "body": body}


async def _screenshot_safety_check(host, page: Any) -> tuple[bool, str]:
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
    if len(body) > host._SCREENSHOT_SCAN_LIMIT:
        return False, "页面正文过长，无法可靠脱敏"
    if host._debug_body_has_sensitive_token(body):
        return False, "页面正文疑似含敏感值，未保存截图"
    return True, ""


def _note_quiet(page: Any, where: str, exc: BaseException) -> None:
    """Record a swallowed best-effort failure into the page debug trace.

    These failures never change flow semantics (optional instrumentation,
    fallback paths, cleanup); the trace entry keeps them observable when a
    nearby operation does fail and the artifacts are inspected.
    """
    try:
        trace = getattr(page, "_gptphone_debug_trace", None)
        if isinstance(trace, _DebugTrace):
            trace.add("quiet_failure", where=str(where or "")[:60], error=type(exc).__name__)
    except Exception:
        # Even the quiet note must not break the surrounding best-effort path.
        return


class _DebugTrace:
    """Small, credential-free page event ring buffer."""

    def __init__(self, limit: int = 100) -> None:
        self.events: Deque[dict[str, Any]] = deque(maxlen=max(10, int(limit)))
        self.lock = threading.Lock()

    def add(self, kind: str, **fields: Any) -> None:
        event: dict[str, Any] = {
            "kind": _host_mod().clean(kind, 40),
            "at": round(time.time(), 3),
        }
        for key, value in fields.items():
            if value in (None, ""):
                continue
            if key in {"url", "safe_page"}:
                value = _host_mod()._safe_event_url(value) or ("" if not value else "页面地址未知")
            elif key in {"status"}:
                try:
                    value = max(0, min(599, int(value)))
                except (TypeError, ValueError):
                    continue
            else:
                value = _host_mod()._sanitize_debug_text(value, 300)
            if value not in (None, ""):
                event[_host_mod().clean(key, 40)] = value
        with self.lock:
            self.events.append(event)

    def snapshot(self) -> list[dict[str, Any]]:
        with self.lock:
            return [dict(item) for item in self.events]


def _page_debug_trace(host, page: Any) -> host._DebugTrace:
    trace = getattr(page, "_gptphone_debug_trace", None)
    if isinstance(trace, host._DebugTrace):
        return trace
    trace = host._DebugTrace()
    try:
        setattr(page, "_gptphone_debug_trace", trace)
    except Exception as exc:
        # Trace attachment is optional instrumentation on the page; keep the
        # returned trace working even when the page object rejects attributes.
        _note_quiet(page, "trace_attach", exc)
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
            def request_failed(request: Any) -> None:
                failure = getattr(request, "failure", "")
                if callable(failure):
                    failure = failure()
                trace.add(
                    "request_failed", method=getattr(request, "method", ""),
                    url=getattr(request, "url", ""), failure=failure,
                )

            on("requestfailed", request_failed)
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


async def _capture_debug_dom(host, page: Any) -> dict[str, Any]:
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
        row: dict[str, Any] = {"tag": host.clean(item.get("tag"), 20)}
        for key in ("role", "type", "aria_label", "text"):
            value = host._sanitize_debug_text(item.get(key), 240)
            if value:
                row[key] = value
        href = host._safe_event_url(item.get("href"))
        if href:
            row["href"] = href
        elements.append(row)
    return {
        "title": host._sanitize_debug_text(raw.get("title"), 160),
        "url": host._safe_event_url(raw.get("url")),
        "elements": elements,
    }


_ARTIFACT_LOCK = threading.RLock()
_ARTIFACT_PROTECTED_SESSIONS: set[str] = set()
_ARTIFACT_SESSION_RE = re.compile(r"^cam-debug-[0-9a-f]{12}$")


def _atomic_artifact_write(host, path: Path, payload: Any) -> None:
    """Write one debug artifact atomically inside its target directory."""
    try:
        from ..atomic_io import atomic_write_json
    except ImportError:  # pragma: no cover - top-level recovery import
        from atomic_io import atomic_write_json  # type: ignore[no-redef]
    atomic_write_json(path, payload)
    # 0600 mirrors the previous NamedTemporaryFile contract so a failure
    # scene can never become world-readable.
    try:
        os.chmod(path, 0o600)
    except OSError as exc:
        _note_stderr("artifact_chmod", exc)


def _trim_debug_artifacts(host, artifact_root: Path, *, current_session: str = "") -> None:
    """Keep at most 50 generated scenes without deleting active sessions."""
    with host._ARTIFACT_LOCK:
        protected = set(host._ARTIFACT_PROTECTED_SESSIONS)
        if current_session:
            protected.add(current_session)
        try:
            directories = sorted(
                (
                    item for item in artifact_root.iterdir()
                    if item.is_dir() and host._ARTIFACT_SESSION_RE.fullmatch(item.name)
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
    host,
    *,
    page: Any,
    artifact_root: Path | None,
    session_id: str,
    artifact_id: str,
    summary: Mapping[str, Any],
    trace: host._DebugTrace,
) -> dict[str, Any]:
    """Persist bounded debug evidence, degrading safely when an API is absent."""
    result = {"artifact_id": artifact_id, "artifact_path": "", "screenshot": "skipped", "screenshot_reason": ""}
    if artifact_root is None:
        result["screenshot_reason"] = "未配置现场目录"
        return result
    directory = artifact_root / session_id
    try:
        directory.mkdir(parents=True, exist_ok=True)
        dom = await host._capture_debug_dom(page)
        host._atomic_artifact_write(directory / "dom.json", dom)
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
                    text = host._safe_incident_id(text)
                else:
                    text = host._safe_proxy_fingerprint(text)
                if text:
                    payload[key] = text
            elif key == "task_id":
                text = host._safe_debug_task_id(value)
                if text:
                    payload[key] = text
            elif key == "safe_page":
                # ``safe_page`` has already been reduced to an origin/path by
                # ``host._safe_event_url``.  Running it through the generic failure
                # sanitizer would redact the entire URL again and discard the
                # useful route needed to identify the failed page.
                text = host._safe_event_url(value)
                if text:
                    payload[key] = text
            else:
                text = host._sanitize_debug_text(value, 240)
                if text:
                    payload[key] = text
        payload["artifact_id"] = artifact_id
        payload["dom_file"] = "dom.json"
        payload["events"] = trace.snapshot()
        # Mask every user-editable control. If the browser implementation does
        # not support Playwright's mask option, skip instead of risking an
        # unredacted screenshot.
        screenshot = directory / "screenshot.png"
        screenshot_safe, screenshot_reason = await host._screenshot_safety_check(page)
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
        host._atomic_artifact_write(directory / "summary.json", payload)
        result["artifact_path"] = str(directory)
    except Exception as exc:
        result["screenshot_reason"] = f"现场写入失败（{type(exc).__name__}）"
    # Direct pool callers may intentionally omit an artifact directory.  The
    # live headed context is still useful in that case; artifact retention is
    # simply skipped instead of dereferencing a missing root during cleanup.
    if artifact_root is not None:
        host._trim_debug_artifacts(artifact_root, current_session=session_id)
    return result


async def _close_context_safely(host, context: Any, timeout: float) -> bool:
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


async def _close_async_resource(host, close_fn: Callable[[], Any], timeout: float) -> bool:
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


async def _page_visible_text(host, page: Any) -> str:
    return await host._body_text(page)


async def _hard_proxy_block_reason(host, page: Any) -> str:
    snapshot = await host._snapshot(page)
    combined = f"{snapshot['title']} {snapshot['body']}".casefold()
    marker = next((item for item in host._PROXY_BLOCK_PAGE_MARKERS if item in combined), "")
    if not marker:
        return ""
    return f"ChatGPT 拒绝当前代理（{marker}）"


async def _is_cloudflare_challenge(host, page: Any) -> bool:
    snapshot = await host._snapshot(page)
    combined = f"{snapshot['title']} {snapshot['body']}".casefold()
    return any(marker in combined for marker in (
        "cloudflare", "just a moment", "verify you are human", "turnstile",
        "checking your browser", "performing security verification", "安全验证",
    ))


async def _wait_challenge_then_stop(host, page: Any, *, timeout: float = 30.0) -> None:
    """Wait briefly for a challenge to clear, then stop without bypassing it."""
    if not await host._is_cloudflare_challenge(page):
        return
    deadline = time.monotonic() + max(0.0, float(timeout))
    while time.monotonic() < deadline:
        await asyncio.sleep(2.0)
        if not await host._is_cloudflare_challenge(page):
            return
    raise host.CamoufoxBrowserError(
        "free_camoufox_challenge", "等待 Camoufox 安全验证",
        "Camoufox 页面安全验证未在等待窗口内完成",
        retryable=False, error_code="free_camoufox_security_challenge",
        safe_page=host._safe_url(page), page_type="security",
    )


async def _wait_for_any_selector(host, page: Any, selectors: tuple[str, ...], *, timeout: float = 30.0) -> str | None:
    deadline = time.monotonic() + max(0.1, float(timeout))
    while time.monotonic() < deadline:
        for selector in selectors:
            try:
                locator = page.locator(selector).first
                if await locator.is_visible(timeout=500):
                    return selector
            except Exception:
                continue
        await asyncio.sleep(0.2)
    return None


_ENTRY_HYDRATION_PROBE_INTERVAL_SECONDS = 0.1
_ENTRY_HYDRATION_READY_FLOOR_SECONDS = 0.3

# Positive evidence that the first-party auth bundle has committed content:
# React 18 stamps fiber keys on the DOM nodes it rendered. Only an explicit
# ``true`` shortens the grace; probes that cannot run (test doubles, cross
# -origin quirks) keep the historical bounded sleep.
_ENTRY_HYDRATION_PROBE_SCRIPT = """
() => {
  if (document.readyState === 'loading') return false;
  const nodes = document.querySelectorAll('form, input, button');
  for (const node of nodes) {
    for (const key of Object.keys(node)) {
      if (key.startsWith('__reactFiber$') || key.startsWith('__reactContainer$')) {
        return true;
      }
    }
  }
  return false;
}
"""


async def _page_react_hydrated(page: Any) -> bool:
    """Return True only with positive evidence that React committed the page."""
    evaluate = getattr(page, "evaluate", None)
    if not callable(evaluate):
        return False
    try:
        return bool(await evaluate(_ENTRY_HYDRATION_PROBE_SCRIPT))
    except Exception:
        return False


async def _wait_for_entry_hydration(host, page: Any, *, timeout: float = 1.5) -> None:
    """Give the first-party auth shell time to bind its React submit handler.

    The email input can be painted before the auth bundle has installed its
    delegated submit listener. A native click in that small window reloads
    ``/auth/login`` instead of starting the OAuth transaction. The grace exits
    early only with positive hydration evidence (React fiber keys on rendered
    nodes plus a short floor); any probe failure or missing marker keeps the
    full bounded sleep, so the worst case stays identical to the historical
    fixed wait. Lightweight test and transport doubles do not expose
    Playwright's event API and remain immediate.
    """
    if not callable(getattr(page, "on", None)):
        return
    grace = max(0.0, min(3.0, float(timeout)))
    if grace <= 0.0:
        return
    deadline = time.monotonic() + grace
    floor = time.monotonic() + min(_ENTRY_HYDRATION_READY_FLOOR_SECONDS, grace)
    while time.monotonic() < deadline:
        if time.monotonic() >= floor and await _page_react_hydrated(page):
            return
        await asyncio.sleep(
            min(_ENTRY_HYDRATION_PROBE_INTERVAL_SECONDS, max(0.0, deadline - time.monotonic()))
        )


async def _find_visible_selector(host, page: Any, selectors: tuple[str, ...]) -> str | None:
    for selector in selectors:
        try:
            if await page.locator(selector).first.is_visible(timeout=500):
                return selector
        except Exception:
            continue
    return None


async def _fill_input_like_user(
    host,
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


async def _submit_email_form_stable(host, page: Any, email: str) -> dict[str, Any]:
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
        "reason": host.clean(result.get("reason"), 80),
        "form_present": bool(result.get("form_present")),
        "input_selector": host.clean(result.get("input_selector"), 500),
        "submit_selector": host.clean(result.get("submit_selector"), 500),
    }


async def _click_first(host, page: Any, selectors: tuple[str, ...], *, timeout: float = 8.0) -> str | None:
    deadline = time.monotonic() + max(0.5, float(timeout))
    for selector in selectors:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            locator = page.locator(selector).first
            await locator.wait_for(state="visible", timeout=max(1, int(remaining * 1000)))
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            await locator.click(timeout=max(1, min(5000, int(remaining * 1000))))
            return selector
        except Exception:
            continue
    return None


async def _click_exact_button_text(
    host,
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
                try:
                    await button.click(timeout=3000, no_wait_after=True)
                except TypeError:
                    # Keep lightweight adapters and older Playwright builds
                    # compatible with the dispatch-only recovery contract.
                    await button.click(timeout=3000)
                return label
            except Exception:
                continue
        await asyncio.sleep(0.25)
    return None


async def _wait_for_submit_enabled(host, page: Any, selectors: tuple[str, ...], *, timeout: float = 20.0) -> str | None:
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


async def _submit_visible_form(host, page: Any, selector: str) -> bool | None:
    """Press Enter and report ``None`` when dispatch outcome is uncertain.

    ``False`` is reserved for failures before Playwright was asked to press
    the key.  An exception raised by ``press`` itself can happen after the
    browser dispatched the event, so callers must not treat it as proof that
    submission did not start.
    """
    # A Playwright ``press`` can wait on the auth shell's navigation even when
    # the key event was already dispatched. Use the native form submission
    # contract first so React receives a real submit event while this helper
    # returns immediately; this is still one and only one submission attempt.
    evaluate = getattr(page, "evaluate", None)
    if callable(evaluate):
        try:
            dispatched = await evaluate(
                """
                (selector) => {
                  const input = document.querySelector(selector)
                    || [...document.querySelectorAll('input[type="email"]')]
                      .find(el => el.offsetWidth || el.offsetHeight || el.getClientRects().length);
                  const form = input?.closest('form');
                  if (!form) return false;
                  if (typeof form.requestSubmit === 'function') {
                    // Do not pass a discovered button here. React auth shells
                    // sometimes render the email action as a plain button;
                    // requestSubmit(button) throws for that non-submit type
                    // and incorrectly falls back to a navigation-waiting key
                    // press. The no-argument form API dispatches the valid
                    // submit event for both variants.
                    form.requestSubmit();
                  } else {
                    const submit = [...form.querySelectorAll('button,input[type="submit"]')]
                      .find(el => !el.disabled && el.getAttribute('aria-disabled') !== 'true');
                    if (!submit) return false;
                    submit.click();
                  }
                  return true;
                }
                """,
                selector,
            )
            if dispatched:
                return True
        except Exception as exc:
            # Fall through to the locator path so recovered adapters without
            # a usable DOM evaluation surface retain the old behavior.
            _note_quiet(page, "email_submit_dispatch", exc)
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
    except Exception as exc:
        if action_started:
            host._record_email_submit_action_failure(page, "enter", exc)
        return None if action_started else False


async def _click_visible_submit(host, page: Any, selector: str) -> bool | None:
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
    except Exception as exc:
        if action_started:
            host._record_email_submit_action_failure(page, "click", exc)
        return None if action_started else False


def _record_email_submit_action_failure(host, page: Any, action: str, exc: BaseException) -> None:
    """Keep only a classified, credential-free submit dispatch failure."""
    text = str(exc or "").casefold()
    if host._browser_process_lost(exc):
        category = "browser_process_lost"
    elif "timeout" in text or "timed out" in text:
        category = "action_timeout"
    elif any(marker in text for marker in (
        "not attached", "detached", "stale", "strict mode violation",
    )):
        category = "locator_unavailable"
    elif host._is_transient_navigation_error(exc):
        category = "transport_error"
    else:
        category = "browser_action_error"
    evidence = {
        "action": "click" if action == "click" else "enter",
        "exception_type": type(exc).__name__[:80] or "UnknownError",
        "category": category,
        "safe_page": host._safe_url(page),
    }
    try:
        setattr(page, "_gptphone_email_submit_action_failure", evidence)
    except Exception as exc:
        # Some lightweight or recovered page adapters do not permit custom
        # attributes. The uncertain outcome remains safe; it simply has less
        # local evidence.
        _note_quiet(page, "email_submit_evidence", exc)


async def _email_submit_uncertain_diagnostic(
    host,
    page: Any,
    *,
    reason: str,
    form_present: bool,
    input_selector: str = "",
    submit_selector: str = "",
) -> str:
    """Build a bounded diagnostic for an irreversible email submit attempt."""
    evidence = getattr(page, "_gptphone_email_submit_action_failure", {})
    if not isinstance(evidence, Mapping):
        evidence = {}
    try:
        observed_state = await host._page_state(page)
    except Exception:
        observed_state = "unknown"
    diagnostic = {
        "phase": "entry",
        "reason": reason,
        "form_present": bool(form_present),
        "input_selector": host.clean(input_selector, 120),
        "submit_selector": host.clean(submit_selector, 120),
        "action": host.clean(evidence.get("action"), 20) or "unknown",
        "exception_type": host.clean(evidence.get("exception_type"), 80) or "unavailable",
        "failure_category": host.clean(evidence.get("category"), 80) or "unavailable",
        "safe_page": host._safe_event_url(evidence.get("safe_page")) or host._safe_url(page),
        "observed_page_state": host.clean(observed_state, 40) or "unknown",
    }
    return json.dumps(diagnostic, ensure_ascii=False)[:500]


async def _auth_error_text(host, page: Any) -> str:
    text = await host._page_visible_text(page)
    for token in (
        "Incorrect", "invalid", "Invalid", "account_deactivated", "account_suspended",
        "account_banned", "Authentication Error", "already registered", "already signed up",
        "Email is required", "已有账号",
    ):
        if token in text:
            return token
    return ""


async def _accept_about_you_consents(host, page: Any, log: Callable[[str, str], None]) -> bool:
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


async def _confirm_birthday(host, page: Any, log: Callable[[str, str], None], *, timeout: float = 1.0) -> bool:
    """Confirm the optional birthday modal without delaying every profile.

    The modal is only mounted for some account/profile combinations.  A page
    with no dialog should return after a short mount grace period; once a
    dialog exists, retain the reference flow's full bounded wait so a delayed
    React render is still handled safely.
    """
    selectors = (
        "[role='dialog'] button:has-text('OK')",
        "[role='dialog'] button:has-text('Confirm')",
        "button:has-text('OK')",
    )
    budget = max(0.0, float(timeout))
    deadline = time.monotonic() + budget
    dialog_probe_deadline = min(deadline, time.monotonic() + min(1.0, budget))
    dialog_count_supported = True
    while time.monotonic() <= deadline:
        if dialog_count_supported:
            try:
                dialogs = page.locator("[role='dialog']")
                dialog_count = int(await dialogs.count())
            except Exception:
                dialog_count_supported = False
            else:
                if dialog_count <= 0:
                    if time.monotonic() >= dialog_probe_deadline:
                        return False
                    remaining_probe = max(0.01, dialog_probe_deadline - time.monotonic())
                    await asyncio.sleep(min(0.2, remaining_probe))
                    continue
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
    host,
    page: Any,
    url: str,
    *,
    timeout_ms: int,
    proxy_retryable: bool,
    attempts: int = 1,
    log: Callable[..., Any] | None = None,
    accept_usable_entry: bool = True,
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
            response = await host._goto_with_diagnostics(
                page,
                url,
                timeout_ms=timeout_ms,
                proxy_retryable=proxy_retryable,
                wrap_errors=False,
            )
            await host._wait_challenge_then_stop(page)
            return response
        except host.CamoufoxBrowserError as exc:
            last_error = exc
            if exc.error_code in {"camoufox_navigation_rate_limited", "camoufox_proxy_blocked"}:
                raise
            if getattr(exc, "recycle_required", False):
                raise
            raise
        except Exception as exc:
            last_error = exc
            if host._browser_process_lost(exc):
                failure = host.CamoufoxBrowserError(
                    "free_camoufox_launch", "启动 Camoufox 浏览器池",
                    "Camoufox 浏览器进程已断开", retryable=True,
                    error_code="camoufox_browser_disconnected",
                    diagnostic="category=browser_process_lost; exception_type="
                    f"{type(exc).__name__}", safe_page=host._safe_url(page),
                    page_type="unknown",
                )
                host._mark_recycle_required(failure, "browser process lost during navigation")
                raise failure from exc

            retryable_navigation = (
                host._is_transient_navigation_error(exc)
                or "timeout" in str(exc or "").casefold()
                or type(exc).__name__.casefold() == "error"
            )
            if retryable_navigation:
                hard_block = await host._hard_proxy_block_reason(page)
                if hard_block:
                    failure = host.CamoufoxBrowserError(
                        "free_camoufox_navigation", "打开 Camoufox 注册页面",
                        "Camoufox 页面被代理或上游服务阻断",
                        retryable=bool(proxy_retryable),
                        error_code="camoufox_proxy_blocked",
                        diagnostic=f"category=proxy_blocked; marker={hard_block}",
                        safe_page=host._safe_url(page), page_type="navigation",
                    )
                    failure.proxy_retryable = bool(proxy_retryable)
                    raise failure from exc
                email_selector = await host._wait_for_any_selector(
                    page, EMAIL_SELECTORS, timeout=2,
                )
                if email_selector and accept_usable_entry:
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

            failure = host.CamoufoxBrowserError(
                "free_camoufox_navigation", "打开 Camoufox 注册页面",
                "Camoufox 页面导航失败", retryable=bool(proxy_retryable),
                error_code="camoufox_navigation_failed",
                diagnostic=host._navigation_diagnostic(exc, page),
                safe_page=host._safe_url(page), page_type="navigation",
            )
            failure.proxy_retryable = bool(proxy_retryable)
            raise failure from exc
    raise host.CamoufoxBrowserError(
        "free_camoufox_navigation", "打开 Camoufox 注册页面",
        "Camoufox 页面导航失败", retryable=bool(proxy_retryable),
        error_code="camoufox_navigation_failed",
        diagnostic=host._navigation_diagnostic(last_error, page) if last_error else "category=navigation_error",
        safe_page=host._safe_url(page), page_type="navigation",
    ) from last_error


def _is_navigation_timeout_failure(host, error: BaseException) -> bool:
    """Return whether a wrapped navigation failure is specifically a timeout."""
    if getattr(error, "error_code", "") != "camoufox_navigation_failed":
        return False
    diagnostic = str(getattr(error, "diagnostic", "") or "").casefold()
    return "category=navigation_timeout" in diagnostic


async def _wait_for_post_entry_auth_state(
    host,
    page: Any,
    *,
    timeout: float = 5.0,
    poll_interval: float = 0.25,
) -> str:
    """Confirm a late auth navigation after ``page.goto`` timed out.

    Firefox can finish the redirect and render the auth page while the
    Playwright navigation promise is still pending. This helper only observes
    page state; it never clicks, submits, consumes OTP, or rotates a proxy.
    """
    deadline = time.monotonic() + max(0.0, float(timeout))
    state = await host._page_state(page)
    if state == "security" or state in host._POST_ENTRY_AUTH_STATES:
        return state
    while time.monotonic() < deadline:
        remaining = max(0.01, deadline - time.monotonic())
        await asyncio.sleep(max(0.01, min(float(poll_interval), remaining)))
        state = await host._page_state(page)
        if state == "security" or state in host._POST_ENTRY_AUTH_STATES:
            return state
    return state


async def _response_retry_after(host, response: Any) -> int:
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
    host,
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
    except host.FreeRegisterError:
        raise
    except Exception as exc:
        if not wrap_errors:
            raise
        if host._browser_process_lost(exc):
            failure = host.CamoufoxBrowserError(
                "free_camoufox_launch", "启动 Camoufox 浏览器池",
                "Camoufox 浏览器进程已断开",
                retryable=True, error_code="camoufox_browser_disconnected",
                diagnostic="browser process lost", safe_page=host._safe_url(page), page_type="unknown",
            )
            host._mark_recycle_required(failure, "browser process lost during navigation")
            raise failure from exc
        failure = host.CamoufoxBrowserError(
            "free_camoufox_navigation", "打开 Camoufox 注册页面",
            "Camoufox 页面导航失败",
            retryable=bool(proxy_retryable), error_code="camoufox_navigation_failed",
            diagnostic=host._navigation_diagnostic(exc, page),
            safe_page=host._safe_url(page), page_type="navigation",
        )
        failure.proxy_retryable = bool(proxy_retryable)
        raise failure from exc

    try:
        status = int(getattr(response, "status", 0) or 0)
    except (TypeError, ValueError):
        status = 0
    retry_after = await host._response_retry_after(response)
    body = (await host._body_text(page)).casefold()
    # A Cloudflare/Turnstile document may carry HTTP 403. Classify the
    # security page before the generic proxy-block branch so the manager
    # never rotates or replays the registration around a challenge.
    if await host._is_cloudflare_challenge(page):
        raise host.CamoufoxBrowserError(
            "free_camoufox_challenge", "等待 Camoufox 安全验证",
            "Camoufox 页面返回 Cloudflare/Turnstile 安全验证，已停止自动流程",
            retryable=False, provider_status=status or None,
            provider_code=f"http_{status}" if status else "security_challenge",
            error_code="free_camoufox_security_challenge",
            diagnostic="security challenge page",
            safe_page=host._safe_url(page), page_type="security",
        )
    blocked = any(marker in body for marker in host._PROXY_BLOCK_PAGE_MARKERS)
    if status == 429:
        raise host.CamoufoxBrowserError(
            "free_camoufox_navigation", "打开 Camoufox 注册页面",
            "Camoufox 页面返回业务限流（429），不会自动重放注册",
            retryable=False, provider_status=429, provider_code="http_429",
            retry_after_seconds=retry_after, error_code="camoufox_navigation_rate_limited",
            diagnostic=f"provider_status=429; retry_after={retry_after}s",
            safe_page=host._safe_url(page), page_type="navigation",
        )
    if blocked or status in {403, 407} or status >= 500:
        code = "camoufox_proxy_blocked" if blocked else f"camoufox_navigation_http_{status}"
        failure = host.CamoufoxBrowserError(
            "free_camoufox_navigation", "打开 Camoufox 注册页面",
            "Camoufox 页面被代理或上游服务阻断",
            retryable=bool(proxy_retryable), provider_status=status or None,
            provider_code=f"http_{status}" if status else "proxy_blocked",
            error_code=code, diagnostic="proxy blocked page" if blocked else f"provider_status={status}",
            safe_page=host._safe_url(page), page_type="navigation",
        )
        failure.proxy_retryable = bool(proxy_retryable)
        raise failure
    return response


async def _new_context(
    host,
    browser: Any,
    *,
    proxy: dict[str, Any] | None,
) -> Any:
    """Create a fingerprinted context, with a version-compatible fallback."""
    _, AsyncNewContext = host._load_camoufox_api()
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


async def _visible(host, page: Any, selectors: tuple[str, ...], timeout: int = 500) -> Any | None:
    for selector in selectors:
        try:
            locator = page.locator(selector).first
            if await locator.is_visible(timeout=timeout):
                return locator
        except Exception:
            continue
    return None


async def _fill(host, locator: Any, value: str) -> bool:
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


async def _click(host, page: Any, selectors: tuple[str, ...], timeout: int = 2500) -> bool:
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


async def _submit(host, locator: Any) -> bool:
    try:
        await locator.press("Enter")
        return True
    except Exception:
        return False


async def _browser_signin_url(host, page: Any, email: str) -> str:
    """Use ChatGPT's same-origin signin endpoint when the entry form is late."""
    device_id = str(uuid.uuid4())

    def reference_authorize_url(identifier: str) -> str:
        return "https://auth.openai.com/api/accounts/authorize?" + urlencode({
            "client_id": "app_X8zY6vW2pQ9tR3dE7nK1jL5gH",
            "scope": "openid email profile offline_access model.request model.read organization.read organization.write",
            "response_type": "code",
            "redirect_uri": "https://chatgpt.com/api/auth/callback/openai",
            "audience": "https://api.openai.com/v1",
            "device_id": identifier,
            "prompt": "login",
            "ext-oai-did": identifier,
            "screen_hint": "login_or_signup",
            "login_hint": str(email),
            "state": uuid.uuid4().hex,
        })

    # The direct route is only a recovery for the first-party entry shell.
    # Never turn a third-party page or an untrusted current document into an
    # authorization navigation when the in-page fetch is unavailable.
    current_host = (urlsplit(str(getattr(page, "url", "") or "")).hostname or "").casefold()
    first_party_entry = current_host in {"chatgpt.com", "auth.openai.com"}
    # Recovery may have just clicked the entry shell's Continue action. Wait
    # for that document load to settle before issuing a same-origin fetch;
    # Firefox aborts in-flight page fetches while the shell is replacing its
    # document, which otherwise hides the authorization response as a generic
    # signin fallback failure.
    wait_for_load_state = getattr(page, "wait_for_load_state", None)
    if callable(wait_for_load_state):
        try:
            await wait_for_load_state("domcontentloaded", timeout=5000)
        except TypeError:
            try:
                await wait_for_load_state("domcontentloaded")
            except Exception as exc:
                # A missing load-state event must not block the navigation.
                _note_quiet(page, "load_state_compat", exc)
        except Exception as exc:
            # A missing load-state event must not block the navigation.
            _note_quiet(page, "load_state", exc)
    script = """
    async ({email, deviceId}) => {
      try {
        const csrf = await fetch('https://chatgpt.com/api/auth/csrf', {
          credentials: 'include', headers: {accept: 'application/json'}
        });
        const csrfPayload = await csrf.json();
        const csrfToken = String(csrfPayload?.csrfToken || '');
        if (!csrfToken) return {ok: false, url: ''};
        const cookieMatch = document.cookie.match(/(?:^|;\\s*)oai-did=([^;]+)/i);
        let cookieDeviceId = '';
        try { cookieDeviceId = cookieMatch ? decodeURIComponent(cookieMatch[1]) : ''; } catch (_) {}
        const effectiveDeviceId = cookieDeviceId || deviceId;
        const state = crypto.randomUUID().replace(/-/g, '');
        const query = new URLSearchParams({
          prompt: 'login', 'ext-oai-did': effectiveDeviceId,
          auth_session_logging_id: crypto.randomUUID(),
          screen_hint: 'login_or_signup', login_hint: email
        });
        const body = new URLSearchParams({
          callbackUrl: 'https://chatgpt.com/', csrfToken, json: 'true'
        });
        const response = await fetch(
          'https://chatgpt.com/api/auth/signin/openai?' + query.toString(),
          // Follow the first-party NextAuth redirect like the reference
          // browser flow. The JSON response contains the server-issued
          // transaction state; fabricating a fresh state after a manual
          // redirect can send the browser straight back to /auth/login.
          {method: 'POST', credentials: 'include', redirect: 'follow',
           headers: {'accept': 'application/json', 'content-type': 'application/x-www-form-urlencoded',
                     'origin': 'https://chatgpt.com', 'referer': 'https://chatgpt.com/'},
           body: body.toString()}
        );
        const payload = await response.json().catch(() => ({}));
        let authorizeUrl = String(payload?.url || '');
        if (!authorizeUrl && response.url.includes('auth.openai.com')) {
          authorizeUrl = response.url;
        }
        // Some ChatGPT deployments acknowledge the NextAuth POST with HTTP
        // 200 but omit the JSON ``url``. Preserve the same transaction by
        // constructing the reference authorization route from its public
        // client parameters instead of retrying the email submission.
        if (!authorizeUrl && response.ok) {
          const authorize = new URL('https://auth.openai.com/api/accounts/authorize');
          authorize.search = new URLSearchParams({
            client_id: 'app_X8zY6vW2pQ9tR3dE7nK1jL5gH',
            scope: 'openid email profile offline_access model.request model.read organization.read organization.write',
            response_type: 'code',
            redirect_uri: 'https://chatgpt.com/api/auth/callback/openai',
            audience: 'https://api.openai.com/v1',
            device_id: effectiveDeviceId,
            prompt: 'login',
            'ext-oai-did': effectiveDeviceId,
            screen_hint: 'login_or_signup',
            login_hint: email,
            state,
          }).toString();
          authorizeUrl = authorize.toString();
        }
        const acknowledged = response.ok || response.type === 'opaqueredirect' || response.status === 0;
        return {ok: acknowledged, url: authorizeUrl};
      } catch (_) {
        return {ok: false, url: ''};
      }
    }
    """
    try:
        result = await page.evaluate(script, {"email": str(email), "deviceId": device_id})
    except Exception:
        return reference_authorize_url(device_id) if first_party_entry else ""
    if not isinstance(result, Mapping) or not result.get("ok"):
        return reference_authorize_url(device_id) if first_party_entry else ""
    candidate = str(result.get("url") or "").strip()
    if not candidate:
        # A successful NextAuth acknowledgement can omit its JSON ``url`` in
        # Firefox/Camoufox. Build the same public authorize transaction here,
        # outside the page fetch, so the state machine can still navigate it.
        candidate = reference_authorize_url(device_id)
    try:
        parsed = urlsplit(candidate)
    except (TypeError, ValueError):
        return ""
    # The normal response is the OpenAI authorization route.  Some ChatGPT
    # shells briefly return their own login route (often with an ``email``
    # query) instead; callers handle that as a form-reopen signal.  Never let
    # a malformed or external provider URL enter the browser flow.
    url_host = (parsed.hostname or "").casefold()
    path = (parsed.path or "").casefold().rstrip("/") or "/"
    # A same-origin login URL is an entry shell, not an authorization result.
    # Returning it here makes the state machine reload the shell and can
    # submit the mailbox a second time.  The reference flow's public
    # authorize route is the only valid fallback after a submitted entry.
    if url_host == "chatgpt.com" and path == "/auth/login":
        candidate = reference_authorize_url(device_id)
        parsed = urlsplit(candidate)
        url_host = (parsed.hostname or "").casefold()
        path = (parsed.path or "/").casefold().rstrip("/") or "/"
    trusted = url_host == "auth.openai.com"
    if parsed.scheme.casefold() != "https" or not trusted:
        return ""
    return candidate


def _is_chatgpt_entry_url(host, value: str) -> bool:
    """Return whether a signin response is the ChatGPT entry shell."""
    try:
        parsed = urlsplit(str(value or ""))
    except (TypeError, ValueError):
        return False
    return (
        parsed.scheme.casefold() == "https"
        and (parsed.hostname or "").casefold() == "chatgpt.com"
        and (parsed.path or "").casefold().rstrip("/") == "/auth/login"
    )


async def _page_state(host, page: Any) -> str:
    raw_url = str(getattr(page, "url", "") or "")
    parsed = urlsplit(raw_url)
    url_host = (parsed.hostname or "").casefold()
    path = (parsed.path or "/").casefold().rstrip("/") or "/"
    body = (await host._body_text(page)).casefold()
    title = ""
    if url_host in {"auth.openai.com", "chatgpt.com"}:
        try:
            title = host.clean(await page.title(), 240).casefold()
        except Exception:
            title = ""
    verification_shell = any(
        marker in f"{title} {body}"
        for marker in (
            "check your inbox",
            "enter the verification code",
            "verification code",
            "verify your email",
            "we sent a code",
            "code to your email",
            "收件箱",
            "验证码",
            "验证你的邮箱",
            "验证邮件",
        )
    )
    # The registration flow must never enter a third-party OAuth provider.
    # Keep this explicit so a broad text selector cannot silently turn an
    # entry-shell recovery into a Google login and wait for it as "unknown".
    if url_host.endswith("accounts.google.com") or url_host.endswith("appleid.apple.com"):
        return "external_auth"
    if any(marker in body for marker in ("cloudflare", "verify you are human", "turnstile", "just a moment", "安全验证")):
        return "security"
    # Auth shells can keep the email input mounted while the submitted email
    # request has already transitioned to the verification step.  The page
    # title/body is the stronger signal in that race; checking the email
    # selector first would incorrectly reopen the entry recovery path and may
    # submit the mailbox a second time.
    if verification_shell and url_host in {"auth.openai.com", "chatgpt.com"}:
        if await host._visible(page, PASSWORD_SELECTORS, 250):
            return "signup_password"
        return "otp" if await host._visible(page, OTP_SELECTORS, 250) else "email_verification"
    if url_host == "chatgpt.com" and path in {"", "/"}:
        return "home"
    if url_host == "chatgpt.com" and ("/auth/login" in path or "/login" in path):
        if await host._visible(page, PASSWORD_SELECTORS, 250):
            return "login_password"
        if await host._visible(page, OTP_SELECTORS, 250):
            return "otp"
        return "entry"
    if "auth.openai.com" in url_host:
        if any(marker in path for marker in ("/about-you", "/about_you", "/birthdate", "/profile")):
            return "profile"
        if path in {"/log-in/password", "/login/password"}:
            return "login_password"
        if "password" in path or "new-password" in path:
            return "signup_password"
        if any(marker in path for marker in ("email-verification", "email-otp", "/verify")):
            if await host._visible(page, PASSWORD_SELECTORS, 250):
                return "signup_password"
            return "otp" if await host._visible(page, OTP_SELECTORS, 250) else "email_verification"
        if any(marker in path for marker in ("/authorize", "/callback", "/continue")):
            return "oauth_callback"
        # The auth host can briefly render an email entry shell at /log-in
        # after the same-origin signin fallback. Match the reference flow's
        # selector fallback so it is not classified as an unknown state.
        if await host._visible(page, EMAIL_SELECTORS, 250):
            return "entry"
    if await host._visible(page, PASSWORD_SELECTORS, 250):
        return "signup_password"
    if await host._visible(page, OTP_SELECTORS, 250):
        return "otp"
    if await host._visible(page, NAME_SELECTORS, 250) or await host._visible(page, BIRTHDAY_SELECTORS, 250):
        return "profile"
    return "unknown"


async def _wait_state(host, page: Any, timeout: float, *states: str) -> str:
    deadline = time.monotonic() + max(1.0, float(timeout))
    wanted = set(states)
    current = "unknown"
    while time.monotonic() < deadline:
        current = await host._page_state(page)
        if current in wanted:
            return current
        await asyncio.sleep(0.35)
    return current


async def _accept_consents(host, page: Any) -> None:
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


async def _sync_hidden_birthday_input(host, page: Any, birthdate: str) -> bool:
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


def _reference_age_and_birthdate(host) -> tuple[int, str]:
    """Use the reference flow's adult age range with a matching birthday."""
    age = random.SystemRandom().randint(18, 35)
    today = date.today()
    return age, f"{today.year - age:04d}-{today.month:02d}-{today.day:02d}"



async def _submit_existing_login_password(host, page: Any, password: str) -> bool:
    """Fill and submit a password for an already-existing Free account.

    Existing-account authentication must use the account's saved password;
    the fixed registration password is intentionally never accepted here.
    Resolve the live locator on every call because auth.openai.com can replace
    the form while React hydrates or after a failed click.
    """
    value = str(password or "")
    if not value:
        return False
    selector = await host._wait_for_any_selector(page, LOGIN_PASSWORD_SELECTORS, timeout=15)
    if not selector or not await host._fill_input_like_user(page, selector, value):
        return False
    if await host._click_first(page, LOGIN_PASSWORD_SUBMIT_SELECTORS, timeout=6):
        return True
    # A submit button can disappear while the password input remains attached;
    # use the freshly resolved input as the final, same-form fallback.
    fresh_selector = await host._find_visible_selector(page, LOGIN_PASSWORD_SELECTORS)
    return bool(fresh_selector and await host._submit_visible_form(page, fresh_selector))


async def _click_passwordless_login_switch(host, page: Any) -> bool:
    """Switch a login-password page to the verification-code login path.

    Passwordless accounts never stored a credential, so the login-password
    form cannot be submitted. Click the page's one-time-code entry (link or
    button) once; the main loop then continues through the OTP stage.
    """
    if await host._click_first(page, PASSWORDLESS_SELECTORS, timeout=6):
        return True
    return False


def _stop_requested(host, value: Any) -> bool:
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
    host,
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
    host,
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
    host,
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

    host._deadline_controller_call(deadline_controller, "begin_otp_wait")

    def end_otp_wait_once() -> None:
        nonlocal otp_wait_ended
        with end_lock:
            if otp_wait_ended:
                return
            otp_wait_ended = True
        host._deadline_controller_call(deadline_controller, "end_otp_wait")

    def requested() -> bool:
        return worker_stop.is_set() or host._stop_requested(stop_requested)

    def consume_exception(future: asyncio.Future[Any]) -> None:
        if not future.cancelled():
            try:
                future.exception()
            except BaseException as exc:
                _note_stderr("L2007", exc)

    def discard_awaitable(value: Any) -> None:
        """Close/cancel an async callback result that the caller abandoned."""
        if not inspect.isawaitable(value):
            return
        close = getattr(value, "close", None)
        if callable(close):
            try:
                close()
                return
            except Exception as exc:
                # Best-effort cleanup of a closeable wait handle.
                _note_quiet(page, "wait_handle_close", exc)
        cancel = getattr(value, "cancel", None)
        if callable(cancel):
            try:
                cancel()
            except Exception as exc:
                # Best-effort cancellation must not break the OTP wait loop.
                _note_quiet(page, "wait_handle_cancel", exc)

    result.add_done_callback(consume_exception)

    def publish(kind: str, value: Any) -> None:
        if kind == "worker_exit":
            # The worker exited with nothing pending. If the drain path has
            # abandoned this future (or a race left it pending), wake
            # ``await_cleanup`` immediately instead of burning the full grace
            # period; an already-resolved future needs no signal.
            if abandoned and not result.done():
                result.set_result(None)
            return
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
            value = host._invoke_otp_callback(
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
        finally:
            # Signal loop-side drainers that this worker has exited with no
            # pending awaitable, so a grace wait can stop immediately.
            try:
                loop.call_soon_threadsafe(publish, "worker_exit", None)
            except RuntimeError:
                pass

    thread = threading.Thread(
        target=worker,
        name=f"camoufox-otp-{host.clean(stage_code, 32) or 'wait'}",
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
                    except Exception as exc:
                        # Uncancel bookkeeping must not break the OTP wait loop.
                        _note_quiet(page, "task_uncancel", exc)
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
            except BaseException as exc:
                _note_stderr("L2186", exc)
            end_otp_wait_once()
            return
        # Cooperative mailbox providers normally wake within one poll chunk;
        # retain only a short grace period so browser cleanup remains bounded.
        await await_cleanup(result, 1.5)
        if result.done():
            try:
                discard_awaitable(result.result())
            except BaseException as exc:
                _note_stderr("L2196", exc)
        end_otp_wait_once()

    handoff_started: float | None = None
    try:
        while True:
        # A result that was published at the deadline still belongs to this
        # OTP attempt. Consume it before consulting the active-budget clock;
        # otherwise a zero remaining budget can mask a valid manual submit.
            if host._stop_requested(stop_requested):
                await stop_and_drain()
                raise host.FreeRegisterError(
                    "free_run_stop",
                    "停止 Free 注册",
                    "任务已请求停止，邮箱验证码轮询已中断",
                    retryable=False,
                    error_code="free_run_stop",
                )
            if result.done():
                if host._stop_requested(stop_requested):
                    await stop_and_drain()
                    raise host.FreeRegisterError(
                        "free_run_stop",
                        "停止 Free 注册",
                        "任务已请求停止，邮箱验证码轮询已中断",
                        retryable=False,
                        error_code="free_run_stop",
                    )
                end_otp_wait_once()
                value = await asyncio.shield(result)
                if host._stop_requested(stop_requested):
                    await stop_and_drain()
                    raise host.FreeRegisterError(
                        "free_run_stop",
                        "停止 Free 注册",
                        "任务已请求停止，邮箱验证码轮询已中断",
                        retryable=False,
                        error_code="free_run_stop",
                    )
                return value
            controller = deadline_controller
            prompt_active = host._deadline_controller_bool(controller, "manual_prompt_active")
            handoff_active = host._deadline_controller_bool(controller, "manual_handoff_active")
            post_submit_grace = host._deadline_controller_bool(controller, "manual_submission_grace_active")
            paused = host._deadline_controller_bool(controller, "is_paused")
            expired_value = host._deadline_controller_call(controller, "is_expired")
            if expired_value is host._DEADLINE_CONTROLLER_MISSING:
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
                    requested_handoff = host._deadline_controller_call(
                        controller, "request_manual_handoff"
                    )
                    if requested_handoff is not host._DEADLINE_CONTROLLER_MISSING:
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
                handoff_remaining = host._deadline_controller_call(
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
            remaining_value = host._deadline_controller_call(controller, "remaining")
            if remaining_value is host._DEADLINE_CONTROLLER_MISSING:
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
                    host._deadline_controller_call(controller, "resume_manual", "timeout")
                await stop_and_drain()
                raise host.CamoufoxBrowserError(
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
                if host._stop_requested(stop_requested):
                    await stop_and_drain()
                    raise host.FreeRegisterError(
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


# Every callable here is a private host-injection helper; the public surface
# stays on the free_camoufox_runtime compatibility facade.
__all__: list[str] = []
