"""Browser-side plan re-check entry for camoufox Free accounts.

Builds the synthetic task mapping for ``CamoufoxRegistrationRunner`` with
``plan_recheck=True`` (existing-account browser login -> fresh token + plan
fields -> credential supplements gated on the saved state) and returns the
flow result to the plan-check queue. The shared healthy proxy is allocated by
the queue worker and passed in through ``context["proxy"]``.
"""

from __future__ import annotations

import secrets
import threading
from typing import Any, Callable, Mapping

try:
    from .browser_registry import CamoufoxRegistrationRunner
except ImportError:  # pragma: no cover - top-level recovery import
    from browser_registry import CamoufoxRegistrationRunner  # type: ignore[no-redef]


__all__ = ["build_camoufox_plan_recheck"]


def build_camoufox_plan_recheck(
    *,
    config_provider: Callable[[], Mapping[str, Any]],
    debug_artifact_dir: str = "",
    runner: Any = None,
) -> Callable[[str, Mapping[str, Any], Callable[[str, str], None]], dict[str, Any]]:
    """Build the synchronous browser plan re-check callback.

    The callback signature is ``(row_id, context, log_fn) -> result`` where
    ``result`` carries the refreshed plan fields, access token and any
    credential supplements produced by the browser flow. Raised errors stay
    ``FreeRegisterError`` subclasses so the queue's failure contract applies.
    """

    runner_instance = runner or CamoufoxRegistrationRunner(debug_artifact_dir=debug_artifact_dir)

    def recheck(
        row_id: str,
        context: Mapping[str, Any],
        log_fn: Callable[[str, str], None],
    ) -> dict[str, Any]:
        config = dict(config_provider() or {})
        task_id = f"free-plan-browser-{secrets.token_hex(6)}"
        task: dict[str, Any] = {
            "task_id": task_id,
            "email": str(context.get("email") or ""),
            "mailbox_url": str(context.get("mailbox_url") or ""),
            "mailbox_source": str(context.get("mailbox_source") or "url"),
            "service_token": str(context.get("service_token") or ""),
            "proxy": str(context.get("proxy") or ""),
            "device_id": str(context.get("device_id") or ""),
            "result": {
                "access_token": str(context.get("access_token") or ""),
                "password": str(context.get("password") or ""),
                "totp_secret": str(context.get("totp_secret") or ""),
                "password_status": str(context.get("password_status") or ""),
                "twofa_status": str(context.get("twofa_status") or ""),
            },
        }

        def stage(_task_id: str, code: str) -> None:
            # Stage codes are surfaced through the plan job's own progress
            # fields; the browser flow's stage notifications are not tracked
            # separately for the re-check queue.
            return None

        result = runner_instance(
            task,
            config,
            threading.Event(),
            stage,
            log_fn,
            plan_recheck=True,
        )
        return dict(result)

    return recheck
