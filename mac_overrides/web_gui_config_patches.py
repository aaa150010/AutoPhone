"""Config store patches for the recovered importer, hosted by web_gui.

Every patched callable receives the hosting ``web_gui`` module as its first
``host`` argument so late-bound module globals (including test rebindings of
``_ORIGINAL_*`` names and runtime singletons) keep their original semantics.
"""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any


def patched_config_load(host, self):
    raw = host._read_store_config(self)
    removed_legacy_fields = False
    # These fields belonged to the removed ordinary-SMS plan gate.  Drop them
    # during the next config read so stale local settings cannot re-enable a
    # gate that is no longer part of the SMS workflow.
    for key in (
        "nvtoken",
        "nvtoken_upload",
        "pixel_upload_enabled",
        "allow_free_plan_sms_binding",
        "allow_unknown_plan_sms_binding",
    ):
        if key in raw:
            raw.pop(key, None)
            removed_legacy_fields = True
    raw, email_timeout_migrated = host._migrate_email_timeout_config(raw)
    raw, email_proxy_scope_migrated = host._migrate_email_proxy_scope_config(raw)
    defaults = host._runtime.default_settings(self.data_dir)
    defaults["proxy_scope"] = {
        **dict(defaults.get("proxy_scope") or {}),
        "email": True,
    }
    defaults["email_proxy_scope_strategy_version"] = host._EMAIL_PROXY_SCOPE_STRATEGY_VERSION
    defaults["email_code_timeout"] = host._EMAIL_CODE_TIMEOUT_DEFAULT
    defaults["email_timeout_strategy_version"] = host._EMAIL_TIMEOUT_STRATEGY_VERSION
    if "sms_mode" not in raw:
        smart = raw.get("sms_smart") if isinstance(raw.get("sms_smart"), dict) else {}
        defaults["sms_mode"] = "smart" if host._runtime._as_bool(smart.get("enabled"), True) else "fixed"

    loaded = host._runtime._merge(defaults, raw)
    changed = (
        self._enforce_private_paths(loaded, defaults)
        or email_timeout_migrated
        or email_proxy_scope_migrated
    )
    if "email_otp_verify_attempts" not in raw or raw.get("email_otp_verify_attempts") in (None, ""):
        if loaded.get("email_otp_verify_attempts") != host._EMAIL_OTP_VERIFY_ATTEMPTS_DEFAULT:
            loaded["email_otp_verify_attempts"] = host._EMAIL_OTP_VERIFY_ATTEMPTS_DEFAULT
            changed = True
    else:
        normalized_attempts = host._int_value(
            raw.get("email_otp_verify_attempts"),
            host._EMAIL_OTP_VERIFY_ATTEMPTS_DEFAULT,
            minimum=1,
            maximum=5,
        )
        if loaded.get("email_otp_verify_attempts") != normalized_attempts:
            loaded["email_otp_verify_attempts"] = normalized_attempts
            changed = True
    if "email_otp_resend_on_retry" not in raw or raw.get("email_otp_resend_on_retry") in (None, ""):
        if loaded.get("email_otp_resend_on_retry") != host._EMAIL_OTP_RESEND_ON_RETRY_DEFAULT:
            loaded["email_otp_resend_on_retry"] = host._EMAIL_OTP_RESEND_ON_RETRY_DEFAULT
            changed = True
    else:
        normalized_resend = host._as_enabled(raw.get("email_otp_resend_on_retry"), False)
        if loaded.get("email_otp_resend_on_retry") != normalized_resend:
            loaded["email_otp_resend_on_retry"] = normalized_resend
            changed = True

    try:
        auth_strategy_version = int(raw.get("email_auth_strategy_version") or 0)
    except (TypeError, ValueError):
        auth_strategy_version = 0
    if auth_strategy_version < 2:
        loaded["email_auth_preference"] = "auto"
        loaded["email_auth_strategy_version"] = 2
        changed = True

    try:
        node_timeout_strategy_version = int(raw.get("node_timeout_strategy_version") or 0)
    except (TypeError, ValueError):
        node_timeout_strategy_version = 0
    if node_timeout_strategy_version < 1:
        loaded["node_timeout"] = 45
        loaded["node_timeout_strategy_version"] = 1
        changed = True

    normalized, migrated = host._sms_runtime_ext.migrate_performance_config(loaded)
    normalized = host._performance_runtime_ext.normalize_feature_flags(normalized)
    normalized["dynamic_auth_challenges"] = host._as_enabled(
        raw.get("dynamic_auth_challenges"), True
    )
    normalized.pop("allow_free_plan_sms_binding", None)
    normalized.pop("allow_unknown_plan_sms_binding", None)
    normalized.pop("pixel_upload_enabled", None)
    policy_keys = (
        "performance_policy_version",
        "auto_email_login_concurrency",
        "phone_submission_concurrency",
        "phone_max_attempts",
        "phone_attempts_per_provider",
        "phone_session_cycle_seconds",
        "auth_session_retries",
        "email_code_timeout",
        "email_timeout_strategy_version",
        "email_otp_verify_attempts",
        "email_otp_resend_on_retry",
        "sms_provider_pools",
        "sms_provider",
        "sms_api_keys",
        "sms_api_key",
        "sms_quality_optimization",
        "adaptive_task_concurrency",
        "task_inflight_optimization",
        "task_inflight_limit",
        "openai_connectivity_guard",
        "phone_binding_compatibility",
        "mailbox_result_index_cache",
        "protocol_concurrency_ceiling",
        "dynamic_auth_challenges",
        "proxy_scope",
        "email_proxy_scope_strategy_version",
    )
    if migrated or any(raw.get(key) != normalized.get(key) for key in policy_keys):
        changed = True
    if changed or removed_legacy_fields:
        host._write_store_config(self, normalized)
    return normalized


def patched_config_save(host, self, values):
    previous = host._read_store_config(self)
    cleaned = dict(values or {})
    if "email_proxy_scope_strategy_version" not in cleaned:
        prior_version = previous.get("email_proxy_scope_strategy_version")
        if prior_version is not None:
            cleaned["email_proxy_scope_strategy_version"] = prior_version
    if "proxy_scope" not in cleaned and isinstance(previous.get("proxy_scope"), dict):
        cleaned["proxy_scope"] = copy.deepcopy(previous["proxy_scope"])
    cleaned.pop("nvtoken", None)
    cleaned.pop("nvtoken_upload", None)
    cleaned.pop("pixel_upload_enabled", None)
    cleaned.pop("allow_free_plan_sms_binding", None)
    cleaned.pop("allow_unknown_plan_sms_binding", None)
    if cleaned.get("email_otp_verify_attempts") in (None, ""):
        cleaned["email_otp_verify_attempts"] = host._EMAIL_OTP_VERIFY_ATTEMPTS_DEFAULT
    if cleaned.get("email_otp_resend_on_retry") in (None, ""):
        cleaned["email_otp_resend_on_retry"] = host._EMAIL_OTP_RESEND_ON_RETRY_DEFAULT
    cleaned, _email_timeout_migrated = host._migrate_email_timeout_config(cleaned)
    cleaned, _email_proxy_scope_migrated = host._migrate_email_proxy_scope_config(cleaned)
    normalized, _migrated = host._sms_runtime_ext.migrate_performance_config(cleaned)
    normalized = host._performance_runtime_ext.normalize_feature_flags(normalized)
    normalized["dynamic_auth_challenges"] = host._as_enabled(
        cleaned.get("dynamic_auth_challenges"), True
    )
    normalized.pop("allow_free_plan_sms_binding", None)
    normalized.pop("allow_unknown_plan_sms_binding", None)
    saved = dict(host._ORIGINAL_CONFIG_SAVE(self, normalized) or {})
    for key in (
        "performance_policy_version",
        "auto_email_login_concurrency",
        "phone_submission_concurrency",
        "phone_max_attempts",
        "phone_attempts_per_provider",
        "phone_session_cycle_seconds",
        "auth_session_retries",
        "email_code_timeout",
        "email_timeout_strategy_version",
        "email_otp_verify_attempts",
        "email_otp_resend_on_retry",
        "sms_provider_pools",
        "sms_provider",
        "sms_api_keys",
        "sms_api_key",
        "sms_quality_optimization",
        "adaptive_task_concurrency",
        "task_inflight_optimization",
        "task_inflight_limit",
        "openai_connectivity_guard",
        "phone_binding_compatibility",
        "mailbox_result_index_cache",
        "protocol_concurrency_ceiling",
        "dynamic_auth_challenges",
        "proxy_scope",
        "email_proxy_scope_strategy_version",
    ):
        saved[key] = normalized[key]
    host._write_store_config(self, saved)
    return saved


def patched_task_config(host, self, settings, email, task_id, *, password=""):
    config = host._ORIGINAL_TASK_CONFIG(self, settings, email, task_id, password=password)
    run_mode = str((settings or {}).get("run_mode") or "register").strip().lower()
    relogin = run_mode == "relogin"
    pools = host._sms_provider_pools_from_config(settings or {})
    enabled_pools = [pool for pool in pools if host._as_enabled(pool.get("enabled"), True) and pool.get("api_keys")]
    primary = enabled_pools[0] if enabled_pools else (pools[0] if pools else {})
    keys = host._sms_runtime_ext.legacy_sms_provider_keys(
        pools,
        primary.get("provider") or "smsbower",
    )
    attempts_per_provider = host._int_value(
        (settings or {}).get("phone_attempts_per_provider"),
        15,
        minimum=1,
        maximum=15,
    )
    attempts = min(45, attempts_per_provider * max(1, len(enabled_pools)))
    phone_seconds = host._int_value(
        (settings or {}).get("phone_session_cycle_seconds"),
        1800,
        minimum=30,
        maximum=1800,
    )
    route_lease_seconds = (
        2 * host._int_value(config.get("code_timeout"), 30, minimum=5, maximum=300)
    ) + 20
    raw_email_attempts = (settings or {}).get("email_otp_verify_attempts")
    email_attempts = host._int_value(
        raw_email_attempts,
        host._EMAIL_OTP_VERIFY_ATTEMPTS_DEFAULT,
        minimum=1,
        maximum=5,
    )
    raw_email_resend = (settings or {}).get("email_otp_resend_on_retry")
    email_resend = host._as_enabled(raw_email_resend, host._EMAIL_OTP_RESEND_ON_RETRY_DEFAULT)
    config.update(
        {
            "sms_provider_pools": pools,
            "sms_provider": str(primary.get("provider") or "smsbower"),
            "sms_api_keys": keys,
            "sms_api_key": keys[0] if keys else "",
            "sms_task_id": str(task_id),
            "phone_max_attempts": attempts,
            "phone_attempts_per_provider": attempts_per_provider,
            "phone_session_cycle_seconds": phone_seconds,
            "phone_session_max_seconds": phone_seconds,
            "phone_retry_sleep_seconds": 1,
            "email_otp_verify_attempts": email_attempts,
            "email_otp_resend_on_retry": email_resend,
            "sms_quality_optimization": host._performance_runtime_ext.as_bool(
                (settings or {}).get("sms_quality_optimization"),
                True,
            ),
            "dynamic_auth_challenges": host._as_enabled(
                (settings or {}).get("dynamic_auth_challenges"), True
            ),
            "phone_binding_compatibility": host._performance_runtime_ext.as_bool(
                (settings or {}).get("phone_binding_compatibility"),
                True,
            ),
        }
    )
    risk_status = host._actionable_phone_risk_status(email)
    if risk_status.get("active"):
        config["_phone_risk_retry"] = True
        config["_phone_risk_reason_code"] = str(
            risk_status.get("reason_code") or "oauth_session_invalid"
        )
    normalized_email = str(email or "").strip().lower()
    results_value = str((settings or {}).get("results_dir") or "results").strip() or "results"
    results_dir = Path(results_value)
    if not results_dir.is_absolute():
        results_dir = Path(getattr(self, "data_dir", host._RUNTIME_DATA_DIR)) / results_dir
    historical = host._mailbox_admin_ext.latest_sub2_accounts_by_email(results_dir).get(
        normalized_email
    )
    if relogin:
        binding = next(
            (
                item
                for item in (settings or {}).get("_gptphone_relogin_rows") or ()
                if isinstance(item, dict)
                and str(item.get("email") or "").strip().lower() == normalized_email
                and str(item.get("sub2api_account_id") or "").strip()
            ),
            None,
        )
        if binding is None:
            raise RuntimeError(
                "relogin_sub2_binding_missing: 重登邮箱缺少经过校验的 SUB2 原账号绑定"
            )
        config["run_mode"] = "relogin"
        config["sms_provider"] = "smsbower"
        config["sms_api_key"] = "relogin-disabled"
        config["sms_api_keys"] = ["relogin-disabled"]
        remote_id = str(binding.get("sub2api_account_id") or "").strip()
        config["_sub2_update_existing"] = {
            "account_id": remote_id,
            "openai_account_id": host._sub2_binding_runtime_ext.historical_openai_account_id(
                historical, remote_id
            ),
            "email": normalized_email,
            "status_code": binding.get("status_code"),
            "status_kind": str(binding.get("status_kind") or "").strip().lower(),
        }
    elif historical:
        update_binding = host._sub2_binding_runtime_ext.resolve_existing_update_binding(
            historical,
            direct_status_lookup=getattr(host._OPENAI_DIRECT_RUNTIME, "status_for", None),
            sub2_status_lookup=getattr(host._SUB2_RUNTIME, "status_for", None),
        )
        if update_binding:
            config["_sub2_update_existing"] = {**update_binding, "email": normalized_email}
    for pool in pools:
        provider = str(pool.get("provider") or "")
        if not provider:
            continue
        provider_keys = list(pool.get("api_keys") or [])
        config[provider] = {
            **dict(config.get(provider) or {}),
            "api_key": provider_keys[0] if provider_keys else "",
        }
    config["sms_smart"] = {
        **dict(config.get("sms_smart") or {}),
        "enabled": True,
        "throughput_priority": False,
        "route_hard_max_inflight": 2,
        "route_max_inflight": 2,
        "route_semi_max_inflight": 2,
        "route_hot_max_inflight": 2,
        "route_lease_seconds": route_lease_seconds,
        "timeout_cooldown": 180,
        "phone_rejected_cooldown": 180,
        "register_rejected_cooldown": 60,
        "register_rejected_min_cooldown": 180,
    }
    return config
