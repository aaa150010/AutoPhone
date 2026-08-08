"""Pure configuration policies for optional runtime performance features."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

try:
    from .sms_provider_runtime import (
        legacy_sms_provider_keys,
        normalize_sms_provider_pools,
    )
except ImportError:  # Loaded as a top-level runtime override by web_gui.py.
    from sms_provider_runtime import (  # type: ignore[no-redef]
        legacy_sms_provider_keys,
        normalize_sms_provider_pools,
    )


SMS_QUALITY_OPTIMIZATION = "sms_quality_optimization"
ADAPTIVE_TASK_CONCURRENCY = "adaptive_task_concurrency"
PERFORMANCE_FEATURE_DEFAULTS = {
    SMS_QUALITY_OPTIMIZATION: True,
    ADAPTIVE_TASK_CONCURRENCY: True,
}
PERFORMANCE_POLICY_VERSION = 11
PHONE_MAX_ATTEMPTS_LIMIT = 45
PERFORMANCE_DEFAULTS = {
    "auto_email_login_concurrency": 5,
    "phone_submission_concurrency": 2,
    "pixel_upload_concurrency": 2,
    "phone_max_attempts": PHONE_MAX_ATTEMPTS_LIMIT,
    "phone_attempts_per_provider": 15,
    "phone_session_cycle_seconds": 1800,
    "auth_session_retries": 1,
}

_TRUE_VALUES = frozenset({"1", "true", "yes", "on", "enabled"})
_FALSE_VALUES = frozenset({"0", "false", "no", "off", "disabled"})


def as_bool(value: Any, default: bool = True) -> bool:
    """Normalize persisted/UI boolean values without making non-empty strings truthy."""
    if value is None or value == "":
        return bool(default)
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in _TRUE_VALUES:
            return True
        if normalized in _FALSE_VALUES:
            return False
        return bool(default)
    return bool(value)


def normalize_feature_flags(value: Any) -> dict[str, Any]:
    """Return a copy with both rollback switches present as real booleans."""
    config = dict(value or {}) if isinstance(value, Mapping) else {}
    for key, default in PERFORMANCE_FEATURE_DEFAULTS.items():
        config[key] = as_bool(config.get(key), default)
    return config


def migrate_performance_config(value: Any) -> tuple[dict[str, Any], bool]:
    """Apply one-time performance defaults while preserving later user choices."""
    config = dict(value or {}) if isinstance(value, dict) else {}
    try:
        version = int(config.get("performance_policy_version") or 0)
    except (TypeError, ValueError):
        version = 0
    migrated = version < PERFORMANCE_POLICY_VERSION
    if migrated:
        for key, default in PERFORMANCE_DEFAULTS.items():
            missing = key not in config or config.get(key) in (None, "")
            try:
                current = int(config.get(key)) if not missing else 0
            except (TypeError, ValueError):
                current = 0
                missing = True
            invalid = current < 0 if key == "auth_session_retries" else current <= 0
            if missing or invalid or (
                version < PERFORMANCE_POLICY_VERSION
                and (
                    (key == "auto_email_login_concurrency" and current == 1)
                    or (key == "phone_max_attempts" and current in {9, 15})
                    or (key == "phone_session_cycle_seconds" and current == 480)
                )
            ):
                config[key] = default
        config["performance_policy_version"] = PERFORMANCE_POLICY_VERSION
    else:
        for key, default in PERFORMANCE_DEFAULTS.items():
            if key not in config:
                config[key] = default

    try:
        phone_max_attempts = int(config.get("phone_max_attempts") or 0)
    except (TypeError, ValueError):
        phone_max_attempts = 0
    if phone_max_attempts > PHONE_MAX_ATTEMPTS_LIMIT:
        config["phone_max_attempts"] = PHONE_MAX_ATTEMPTS_LIMIT

    try:
        task_concurrency = max(1, min(8, int(config.get("concurrency") or 5)))
    except (TypeError, ValueError):
        task_concurrency = 5
    config["concurrency"] = task_concurrency
    try:
        email_concurrency = int(
            config.get("auto_email_login_concurrency")
            or PERFORMANCE_DEFAULTS["auto_email_login_concurrency"]
        )
    except (TypeError, ValueError):
        email_concurrency = PERFORMANCE_DEFAULTS["auto_email_login_concurrency"]
    config["auto_email_login_concurrency"] = max(
        1,
        min(task_concurrency, email_concurrency),
    )
    for key in ("phone_submission_concurrency", "pixel_upload_concurrency"):
        try:
            parsed = int(config.get(key) or PERFORMANCE_DEFAULTS[key])
        except (TypeError, ValueError):
            parsed = PERFORMANCE_DEFAULTS[key]
        maximum = 5 if key == "phone_submission_concurrency" else 3
        config[key] = max(1, min(maximum, parsed))

    pools = normalize_sms_provider_pools(
        config.get("sms_provider_pools"),
        legacy_provider=config.get("sms_provider") or "smsbower",
        legacy_keys=config.get("sms_api_keys"),
        legacy_key=config.get("sms_api_key"),
    )
    config["sms_provider_pools"] = pools
    config["sms_provider"] = str(pools[0].get("provider") or "smsbower")
    keys = legacy_sms_provider_keys(pools, config["sms_provider"])
    config["sms_api_keys"] = keys
    config["sms_api_key"] = keys[0] if keys else ""
    return config, migrated


@dataclass(frozen=True)
class TaskAdmissionPolicy:
    """Resolved limits for one importer run."""

    base_limit: int
    restore_ceiling: int
    absolute_ceiling: int
    adaptive: bool


def resolve_task_admission(
    configured_limit: Any,
    *,
    run_mode: Any = "register",
    adaptive_enabled: Any = True,
) -> TaskAdmissionPolicy:
    """Enable conservative 8 -> 9 -> 10 admission only for registration runs."""
    try:
        task_limit = max(1, min(8, int(configured_limit)))
    except (TypeError, ValueError):
        task_limit = 5
    register_mode = str(run_mode or "register").strip().lower() == "register"
    adaptive = register_mode and task_limit == 8 and as_bool(adaptive_enabled, True)
    ceiling = 10 if adaptive else task_limit
    return TaskAdmissionPolicy(
        base_limit=task_limit,
        restore_ceiling=ceiling,
        absolute_ceiling=ceiling,
        adaptive=adaptive,
    )


def format_task_admission_event(event: Any) -> tuple[str, str] | None:
    """Format a credential-free admission event for the recovered logger."""
    value = dict(event or {}) if isinstance(event, Mapping) else {}
    try:
        old_limit = max(0, int(value.get("old_limit") or 0))
        new_limit = max(0, int(value.get("new_limit") or 0))
    except (TypeError, ValueError):
        return None
    if old_limit <= 0 or new_limit <= 0:
        return None
    kind = str(value.get("kind") or "")
    if kind == "restored":
        return (
            f"[任务并发/registration_admission] 连续成功，任务并发 {old_limit} -> {new_limit}",
            "info",
        )
    if kind == "resource_recovered":
        return (
            f"[任务并发/registration_admission] FD 水位恢复稳定，任务并发 {old_limit} -> {new_limit}",
            "info",
        )
    try:
        pause_seconds = max(0, int(value.get("pause_seconds") or 0))
    except (TypeError, ValueError):
        pause_seconds = 0
    reason = str(value.get("reason") or "")
    if kind == "resource_exhausted" or reason == "resource_fd_exhausted":
        return (
            "[任务并发/registration_admission] 文件描述符耗尽，"
            f"任务并发 {old_limit} -> {new_limit}，暂停新任务 {pause_seconds} 秒",
            "warn",
        )
    return (
        "[任务并发/registration_admission] 基础设施压力达到阈值，"
        f"任务并发 {old_limit} -> {new_limit}，暂停新任务 {pause_seconds} 秒",
        "warn",
    )
