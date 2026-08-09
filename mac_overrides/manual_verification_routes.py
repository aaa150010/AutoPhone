"""Flask integration for task-scoped manual verification input."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from flask import jsonify, request

try:
    from .manual_verification_runtime import (
        ManualVerificationBroker,
        ManualVerificationError,
        normalize_generation,
        normalize_input_kind,
        validate_code,
    )
except ImportError:
    from manual_verification_runtime import (
        ManualVerificationBroker,
        ManualVerificationError,
        normalize_generation,
        normalize_input_kind,
        validate_code,
    )


def patch_flask_app(
    app: Any,
    *,
    broker: ManualVerificationBroker,
    task_exists: Callable[[str], bool] | None = None,
    task_generation: Callable[[str], Any] | None = None,
) -> Any:
    if getattr(app, "_gptphone_manual_verification_patched", False):
        return app

    def submit_manual_verification():
        data = request.get_json(silent=True)
        if not isinstance(data, Mapping):
            return jsonify(ok=False, error_code="invalid_payload", error="请求必须是 JSON 对象"), 400
        task_id = str(data.get("task_id") or "").strip()
        # Validate the request shape before consulting task state.  This keeps
        # malformed requests at 400 even when the task has already been
        # removed, while allowing the broker to classify a valid late code
        # against its short-lived stopped/expired tombstone.
        if not task_id:
            return jsonify(ok=False, error_code="invalid_prompt", error="人工验证码上下文无效"), 400
        input_kind = normalize_input_kind(data.get("input_kind"))
        if not input_kind:
            return jsonify(ok=False, error_code="invalid_input_kind", error="验证码类型不受支持"), 400
        requested_generation = normalize_generation(data.get("generation"))
        if requested_generation < 0:
            return jsonify(ok=False, error_code="invalid_prompt", error="人工验证码上下文无效"), 400
        try:
            # Do this before the task-existence lookup as well; a malformed
            # code must never be reported as an unknown task or 410.
            validate_code(input_kind, data.get("code"))
        except ManualVerificationError as exc:
            return jsonify(ok=False, error_code=exc.code, error=str(exc)), exc.status
        # Let the broker classify an expired/stopped tombstone first.  A
        # newer task generation must not mask the required 410 response.
        prompt_visible = True
        public_prompt = getattr(broker, "public", None)
        if callable(public_prompt):
            try:
                prompt_visible = bool(public_prompt(task_id))
            except Exception:
                prompt_visible = True
        if requested_generation >= 0 and prompt_visible and callable(task_generation):
            try:
                current_generation = normalize_generation(task_generation(task_id))
            except Exception:
                # The broker remains the source of truth if a recovered task
                # snapshot is temporarily unavailable.
                current_generation = -1
            if current_generation >= 0 and current_generation != requested_generation:
                return (
                    jsonify(
                        ok=False,
                        error_code="stale_generation",
                        error="验证码输入已过期，请使用当前任务提示",
                    ),
                    409,
                )
        try:
            result = broker.submit(
                task_id,
                input_kind,
                data.get("generation"),
                data.get("code"),
            )
        except ManualVerificationError as exc:
            # A task may disappear from the public task map immediately after
            # it stops.  Preserve the broker's 410/409 tombstone classification
            # for that race, and only translate a genuinely unknown task when
            # the broker has no prompt or tombstone for it.
            if (
                exc.code == "not_waiting"
                and exc.status == 404
                and callable(task_exists)
            ):
                try:
                    exists = bool(task_exists(task_id))
                except Exception:
                    exists = True
                if not exists:
                    return jsonify(ok=False, error_code="task_not_found", error="任务不存在"), 404
            return jsonify(ok=False, error_code=exc.code, error=str(exc)), exc.status
        return jsonify(ok=True, **result)

    app.add_url_rule(
        "/api/runtime/tasks/manual-verification",
        "gptphone_manual_verification",
        submit_manual_verification,
        methods=["POST"],
    )
    app._gptphone_manual_verification_patched = True
    return app


__all__ = ["patch_flask_app"]
