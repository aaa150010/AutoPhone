"""Playwright/Camoufox page transport adapter.

Business state transitions should depend on this small interface instead of
calling locator methods throughout the flow.  The adapter intentionally uses
duck typing so tests can provide tiny fake pages and both Playwright API
variants remain supported.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import inspect
import re
from typing import Any, Iterable
from urllib.parse import urlsplit


class CamoufoxTransportError(RuntimeError):
    """A page operation failed after selector fallbacks were exhausted."""


def _fail_closed_snapshot_text(value: Any, limit: int) -> str:
    """Redact a snapshot even when the shared sanitizer is unavailable."""
    text = str(value or "")[: max(0, int(limit))]
    # Keep this fallback deliberately small and conservative.  It is used only
    # when importing/calling ``debug_artifacts.sanitize_debug_text`` failed;
    # returning the raw page body in that branch would turn an observability
    # failure into a credential disclosure.
    text = re.sub(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", "<邮箱>", text)
    text = re.sub(r"(?<!\d)\d{4,7}(?!\d)", "<验证码>", text)
    text = re.sub(r"(?i)\b(?:bearer|basic)\s+[^\s,;]+", "<授权头>", text)
    text = re.sub(
        r"(?i)\b(access[_ -]?token|refresh[_ -]?token|id[_ -]?token|password|cookie|secret|authorization)\s*[:=]\s*[^\s,;]+",
        r"\1=<已隐藏>",
        text,
    )
    text = re.sub(r"(?i)(https?|socks5?h?)://[^\s<>\"']+", "<地址已隐藏>", text)
    return text[: max(0, int(limit))]


def _selector_tuple(selectors: Iterable[str] | str) -> tuple[str, ...]:
    if isinstance(selectors, str):
        return (selectors,)
    return tuple(str(item) for item in selectors if str(item).strip())


async def _await_maybe(value: Any) -> Any:
    """Accept both async Playwright methods and lightweight sync test doubles."""

    return await value if inspect.isawaitable(value) else value


def _supports_keyword(method: Any, name: str) -> bool:
    """Check an optional Playwright keyword without invoking the action twice."""

    try:
        signature = inspect.signature(method)
    except (TypeError, ValueError):
        # Opaque wrappers are assumed to support the current API.  A failure
        # is reported by the caller rather than replaying a side-effecting
        # browser action with a second call shape.
        return True
    return name in signature.parameters or any(
        parameter.kind is inspect.Parameter.VAR_KEYWORD
        for parameter in signature.parameters.values()
    )


def _safe_page_url(page: Any) -> str:
    """Reduce a page URL to the canonical redacted origin/path projection."""

    raw = str(getattr(page, "url", "") or "")
    try:
        from .. import free_camoufox_runtime
        reducer = getattr(free_camoufox_runtime, "_safe_url", None)
        if callable(reducer):
            return str(reducer(page) or "")[:500]
    except Exception:
        pass
    try:
        parsed = urlsplit(raw)
        if not parsed.scheme or not parsed.hostname:
            return ""
        # Never retain query/fragment components in the fallback path.
        host = parsed.hostname
        trusted = (
            host.casefold() == "chatgpt.com"
            or host.casefold().endswith(".chatgpt.com")
            or host.casefold() == "openai.com"
            or host.casefold().endswith(".openai.com")
        )
        path = parsed.path or "/"
        if not trusted:
            path = "/[路径已隐藏]"
        return f"{parsed.scheme.lower()}://{host}{path}"[:500]
    except Exception:
        return ""


@dataclass(frozen=True, slots=True)
class TransportOperation:
    operation: str
    selector: str = ""
    ok: bool = False
    detail: str = ""


class CamoufoxTransport:
    """Small, retry-free adapter for common page interactions.

    Retry policy belongs to the state machine/runner.  Keeping this adapter
    retry-free makes a click or fill deterministic and easy to unit test.
    """

    def __init__(self, page: Any, *, default_timeout_ms: int = 500) -> None:
        self.page = page
        self.default_timeout_ms = max(0, int(default_timeout_ms))

    def locator(self, selector: str) -> Any:
        factory = getattr(self.page, "locator", None)
        if not callable(factory):
            raise CamoufoxTransportError("页面不支持 locator")
        item = factory(selector)
        return getattr(item, "first", item)

    async def visible(
        self,
        selectors: Iterable[str] | str,
        *,
        timeout_ms: int | None = None,
    ) -> tuple[str, Any] | None:
        timeout = self.default_timeout_ms if timeout_ms is None else max(0, int(timeout_ms))
        for selector in _selector_tuple(selectors):
            try:
                item = self.locator(selector)
                if await _await_maybe(item.is_visible(timeout=timeout)):
                    return selector, item
            except Exception:
                continue
        return None

    async def wait_for_any(
        self,
        selectors: Iterable[str] | str,
        *,
        timeout: float = 30.0,
        poll_interval: float = 0.1,
    ) -> str | None:
        deadline = asyncio.get_running_loop().time() + max(0.0, float(timeout))
        while True:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining < 0:
                return None
            # Keep selector probing inside the caller's deadline even when a
            # Playwright locator uses a relatively large default timeout.
            probe_timeout = min(self.default_timeout_ms, max(0, int(remaining * 1000)))
            found = await self.visible(selectors, timeout_ms=probe_timeout)
            if found is not None:
                return found[0]
            if asyncio.get_running_loop().time() >= deadline:
                return None
            await asyncio.sleep(max(0.01, float(poll_interval)))

    async def fill(
        self,
        selector_or_locator: str | Any,
        value: Any,
        *,
        click: bool = True,
    ) -> bool:
        item = self.locator(selector_or_locator) if isinstance(selector_or_locator, str) else selector_or_locator
        text = str(value)
        try:
            if click:
                await _await_maybe(item.click())
            await _await_maybe(item.fill(""))
            await _await_maybe(item.fill(text))
            return True
        except Exception:
            try:
                await _await_maybe(item.fill(text))
                return True
            except Exception:
                return False

    async def click(
        self,
        selectors: Iterable[str] | str,
        *,
        timeout_ms: int = 2500,
    ) -> str | None:
        timeout = max(0, int(timeout_ms))
        for selector in _selector_tuple(selectors):
            try:
                item = self.locator(selector)
                if not await _await_maybe(item.is_visible(timeout=min(500, timeout))):
                    continue
                enabled = getattr(item, "is_enabled", None)
                if callable(enabled) and not await _await_maybe(enabled(timeout=min(500, timeout))):
                    continue
                # Navigation completion is owned by the state-machine poller.
                # Playwright's default waits for an initiated navigation and
                # can raise after the click was already dispatched when the
                # auth shell is slow, making a successful submit look failed.
                click = getattr(item, "click")
                if _supports_keyword(click, "no_wait_after"):
                    await _await_maybe(click(timeout=timeout, no_wait_after=True))
                else:  # compatibility with older Playwright/test doubles
                    await _await_maybe(click(timeout=timeout))
                return selector
            except Exception:
                continue
        return None

    async def submit(self, selector_or_locator: str | Any) -> bool:
        item = self.locator(selector_or_locator) if isinstance(selector_or_locator, str) else selector_or_locator
        try:
            # The caller's state loop owns navigation observation.  Waiting
            # inside Playwright can time out after Enter was already
            # dispatched by a slow auth redirect.
            press = getattr(item, "press")
            if _supports_keyword(press, "no_wait_after"):
                await _await_maybe(press("Enter", no_wait_after=True))
            else:  # compatibility with older Playwright/test doubles
                await _await_maybe(press("Enter"))
            return True
        except Exception:
            return False

    async def body_text(self, *, timeout_ms: int = 1500) -> str:
        try:
            body = self.page.locator("body")
            return str(await _await_maybe(body.inner_text(timeout=timeout_ms)) or "")
        except Exception:
            return ""

    async def title(self) -> str:
        try:
            return str(await _await_maybe(self.page.title()) or "")
        except Exception:
            return ""

    async def evaluate(self, script: str, arg: Any = None, *, timeout: float = 3.0) -> Any:
        evaluator = getattr(self.page, "evaluate", None)
        if not callable(evaluator):
            raise CamoufoxTransportError("页面不支持 evaluate")
        result = evaluator(script, arg) if arg is not None else evaluator(script)
        if inspect.isawaitable(result):
            return await asyncio.wait_for(result, timeout=max(0.1, float(timeout)))
        return result

    async def page_state(self) -> str:
        """Classify the current page through the canonical runtime classifier.

        The fallback intentionally reports only coarse states.  Production
        callers should use the legacy classifier until the full state machine
        is migrated; this method gives new code one stable call site.
        """

        try:
            from .. import free_camoufox_runtime
            classifier = getattr(free_camoufox_runtime, "_page_state", None)
        except Exception:  # pragma: no cover - top-level recovery import
            classifier = None
        if callable(classifier):
            try:
                value = classifier(self.page)
                if inspect.isawaitable(value):
                    value = await value
                return str(value or "unknown")
            except Exception:
                # Classification is observational; a detached page should be
                # reported as unknown and handled by the runner's error policy.
                return "unknown"
        host = (urlsplit(str(getattr(self.page, "url", "") or "")).hostname or "").casefold()
        return "home" if host == "chatgpt.com" else "unknown"

    async def snapshot(self) -> dict[str, str]:
        """Return a bounded page snapshot without serializing form values."""
        try:
            raw_body = await self.body_text()
        except Exception:
            raw_body = ""
        try:
            raw_title = await self.title()
        except Exception:
            raw_title = ""
        try:
            from .debug_artifacts import sanitize_debug_text
            body = sanitize_debug_text(raw_body, 1800)
            title = sanitize_debug_text(raw_title, 160, mask_bare_numeric=False)
        except Exception:
            body = _fail_closed_snapshot_text(raw_body, 1800)
            title = _fail_closed_snapshot_text(raw_title, 160)
        try:
            url = _safe_page_url(self.page)
        except Exception:
            # A URL is useful only if it passed the same origin/path reducer;
            # never fall back to echoing an arbitrary page URL here.
            url = ""
        return {
            "url": url,
            "title": title,
            "body": body,
            "state": await self.page_state(),
        }

    async def goto(self, url: str, **kwargs: Any) -> Any:
        """Navigate once; retry decisions stay in the runner policy."""

        navigate = getattr(self.page, "goto", None)
        if not callable(navigate):
            raise CamoufoxTransportError("页面不支持 goto")
        return await _await_maybe(navigate(str(url), **kwargs))


class PageTransportContract:
    """Structural helper used by tests and dependency injection."""

    REQUIRED_METHODS = (
        "visible", "wait_for_any", "fill", "click", "submit", "body_text", "evaluate", "goto",
    )

    @classmethod
    def check(cls, transport: Any) -> tuple[bool, tuple[str, ...]]:
        missing = tuple(name for name in cls.REQUIRED_METHODS if not callable(getattr(transport, name, None)))
        return not missing, missing


_LEGACY_FUNCTIONS = {
    # The names below are kept as lazy aliases while the live state machine is
    # migrated in smaller increments.  Resolving them at access time means a
    # missing optional browser dependency cannot break API startup.
    "_goto_with_retry",
    "_goto_with_diagnostics",
    "_new_context",
    "_page_state",
    "_wait_for_any_selector",
    "_find_visible_selector",
    "_fill_input_like_user",
    "_submit_email_form_stable",
    "_click_first",
    "_click_visible_submit",
    "_await_otp_callback",
}


def __getattr__(name: str) -> Any:
    if name in _LEGACY_FUNCTIONS:
        try:
            from .. import free_camoufox_runtime
            return getattr(free_camoufox_runtime, name)
        except Exception as exc:  # pragma: no cover - top-level recovery import
            raise AttributeError(name) from exc
    raise AttributeError(name)


__all__ = [
    "CamoufoxTransport",
    "CamoufoxTransportError",
    "PageTransportContract",
    "TransportOperation",
    *_LEGACY_FUNCTIONS,
]
