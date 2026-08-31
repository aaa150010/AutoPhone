"""Registration runner boundary for the Free Camoufox chain."""

from __future__ import annotations

from typing import Any, Mapping

from .contracts import CamoufoxRegistrationRequest


def _legacy_runner_class() -> Any:
    try:
        from .. import free_camoufox_runtime
        return free_camoufox_runtime.CamoufoxRegistrationRunner
    except Exception:  # pragma: no cover - top-level recovery import
        import free_camoufox_runtime  # type: ignore
        return free_camoufox_runtime.CamoufoxRegistrationRunner


class CamoufoxRunner:
    """Stable composition boundary delegating to the existing runner.

    Keeping this facade intentionally thin allows the state machine and pool
    services to be introduced incrementally without changing manager imports.
    """

    def __init__(self, *, lifecycle_store_path: str = "", debug_artifact_dir: str = "") -> None:
        self.lifecycle_store_path = lifecycle_store_path
        self.debug_artifact_dir = debug_artifact_dir
        self._delegate = _legacy_runner_class()(
            lifecycle_store_path=lifecycle_store_path,
            debug_artifact_dir=debug_artifact_dir,
        )

    @staticmethod
    def preflight(config: Mapping[str, Any]) -> dict[str, Any]:
        return dict(_legacy_runner_class().preflight(config))

    def run(
        self,
        task: Mapping[str, Any],
        config: Mapping[str, Any],
        stop_event: Any,
        stage: Any,
        log: Any,
        *,
        twofa_retry: bool = False,
        password_retry: bool = False,
    ) -> Mapping[str, Any]:
        return self._delegate(
            task,
            config,
            stop_event,
            stage,
            log,
            twofa_retry=twofa_retry,
            password_retry=password_retry,
        )

    __call__ = run

    @property
    def delegate(self) -> Any:
        """Expose the compatibility delegate for diagnostics/tests only."""

        return self._delegate


def runner_from_request(
    request: CamoufoxRegistrationRequest,
    config: Mapping[str, Any],
    stop_event: Any,
    stage: Any,
    log: Any,
    **kwargs: Any,
) -> Mapping[str, Any]:
    """Run a typed request through the compatibility runner."""

    # The legacy continuation contract reads the private account envelope from
    # ``task['result']`` (rather than from top-level request fields).  Keep the
    # bridge explicit so password/2FA retries retain their token and eligibility
    # markers while ordinary signup requests remain unchanged.
    prior_result = request.private_result_snapshot()
    # A caller may construct a typed request directly and omit the explicit
    # retry flag while passing it through kwargs. Preserve the same mapping
    # behavior for that compatibility shape without mutating the request.
    retry_requested = bool(request.password_retry or kwargs.get("password_retry"))
    if retry_requested and request.password_retry_token and not any(
        str(prior_result.get(key) or "").strip() for key in ("access_token", "token")
    ):
        prior_result["access_token"] = request.password_retry_token
    task = {
        "email": request.email,
        "proxy": request.proxy,
        "task_id": request.task_id,
        "batch_id": request.batch_id,
        "password": request.password,
        "saved_password": request.existing_password,
        "password_retry_token": request.password_retry_token,
        "expected_exit_ip": request.expected_exit_ip,
        "result": prior_result,
    }
    options = {
        "twofa_retry": request.force_existing_login,
        "password_retry": request.password_retry,
    }
    options.update(kwargs)
    return CamoufoxRunner()(task, config, stop_event, stage, log, **options)


def __getattr__(name: str) -> Any:
    """Resolve the historical class name without importing it eagerly.

    A number of integrations import ``CamoufoxRegistrationRunner`` directly
    from this package.  Returning the canonical legacy class preserves class
    identity for those callers while keeping optional browser dependencies
    lazy during ordinary package discovery.
    """

    if name == "CamoufoxRegistrationRunner":
        return _legacy_runner_class()
    raise AttributeError(name)


def __dir__() -> list[str]:
    return sorted(set(globals()) | {"CamoufoxRegistrationRunner"})


__all__ = ["CamoufoxRegistrationRunner", "CamoufoxRunner", "runner_from_request"]
