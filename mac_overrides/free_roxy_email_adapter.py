"""Callback adapter between the Roxy runner and the signup email state machine."""

from __future__ import annotations

from typing import Any, Callable

try:
    from .free_roxy_signup import submit_email_and_wait
except ImportError:  # pragma: no cover
    from free_roxy_signup import submit_email_and_wait  # type: ignore[no-redef]


def submit_registration_email(
    driver: Any,
    email: str,
    human: Any,
    log: Callable[[str, str], None] | None,
    timeout: int,
    *,
    classify: Callable[[Any], str],
    wait_security: Callable[[Any, int, Callable[[str, str], None] | None], str],
    type_element: Callable[[Any, str, Any], None],
    click_element: Callable[[Any, Any, Any], None],
    select_auth_window: Callable[..., Any] | None = None,
    attempts: int = 3,
) -> str:
    """Adapt the signup form runner to the Roxy runtime callback contract."""
    return submit_email_and_wait(
        driver, email, human, log, timeout,
        classify=classify,
        wait_security=wait_security,
        type_element=type_element,
        click_element=click_element,
        select_auth_window=select_auth_window,
        attempts=attempts,
    )


__all__ = ["submit_registration_email"]
