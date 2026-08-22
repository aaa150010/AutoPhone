"""Local dashboard configuration policy independent of the recovered runtime."""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import uuid
from collections.abc import Mapping
from typing import Any, Callable


EMAIL_PROXY_SCOPE_STRATEGY_VERSION = 1


def make_email_proxy_scope_migrator(
    *,
    strategy_version: int = EMAIL_PROXY_SCOPE_STRATEGY_VERSION,
) -> Callable[[Any], tuple[dict[str, Any], bool]]:
    """Migrate legacy ordinary mailbox proxy settings once.

    The old dashboard defaulted ``proxy_scope.email`` to false.  A version
    marker makes the upgrade one-shot: an unversioned false value is upgraded
    to true, while a user who later turns it off keeps that choice.
    """

    version_target = int(strategy_version)

    def migrate(value: Any) -> tuple[dict[str, Any], bool]:
        config = dict(value or {}) if isinstance(value, Mapping) else {}
        try:
            version = int(config.get("email_proxy_scope_strategy_version") or 0)
        except (TypeError, ValueError):
            version = 0
        raw_scope = config.get("proxy_scope")
        scope = dict(raw_scope) if isinstance(raw_scope, Mapping) else {}
        migrated = False
        if version < version_target:
            if scope.get("email") is not True:
                scope["email"] = True
                migrated = True
            if config.get("email_proxy_scope_strategy_version") != version_target:
                migrated = True
        elif "email" not in scope:
            # Versioned configs created by an older build may not have the
            # nested key.  Treat that omission as the new safe default.
            scope["email"] = True
            migrated = True
        if config.get("proxy_scope") != scope:
            config["proxy_scope"] = scope
            migrated = True
        if config.get("email_proxy_scope_strategy_version") != version_target:
            config["email_proxy_scope_strategy_version"] = version_target
            migrated = True
        return config, migrated

    return migrate

def _coerce_int(value: Any, default: int, minimum: int | None = None, maximum: int | None = None) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = int(default)
    if minimum is not None:
        parsed = max(int(minimum), parsed)
    if maximum is not None:
        parsed = min(int(maximum), parsed)
    return parsed


def make_email_timeout_migrator(
    *,
    strategy_version: int,
    default_timeout: int,
) -> Callable[[Any], tuple[dict[str, Any], bool]]:
    """Create the compatible timeout migration callable used by both stores."""

    version_target = int(strategy_version)
    timeout_default = int(default_timeout)

    def migrate(value: Any) -> tuple[dict[str, Any], bool]:
        config = dict(value or {})
        try:
            version = int(config.get("email_timeout_strategy_version") or 0)
        except (TypeError, ValueError):
            version = 0
        raw_timeout = config.get("email_code_timeout")
        migrated = version < version_target
        legacy_default_timeouts = {90, 150}
        if migrated and (
            raw_timeout in (None, "")
            or _coerce_int(raw_timeout, timeout_default, minimum=30, maximum=600)
            in legacy_default_timeouts
        ):
            timeout = timeout_default
        else:
            timeout = _coerce_int(
                raw_timeout,
                timeout_default,
                minimum=30,
                maximum=600,
            )
        if config.get("email_code_timeout") != timeout:
            migrated = True
        if config.get("email_timeout_strategy_version") != version_target:
            migrated = True
        config["email_code_timeout"] = timeout
        config["email_timeout_strategy_version"] = version_target
        return config, migrated

    return migrate


def read_store_config(store: Any) -> dict[str, Any]:
    path = getattr(store, "path", store)
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    except Exception:
        return {}
    return value if isinstance(value, dict) else {}


def atomic_write_private_json(path: Any, value: Any) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(value, ensure_ascii=False, indent=2)
    temporary = target.with_name(f".{target.name}.{uuid.uuid4().hex}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, target)
        os.chmod(target, 0o600)
    except BaseException:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise


def write_store_config(store: Any, value: Any) -> None:
    atomic_write_private_json(getattr(store, "path", store), value)


class LocalConfigRuntime:
    """Own config merging, secret preservation, and server-side defaults."""

    def __init__(
        self,
        *,
        clean: Callable[[Any], Any],
        secret_mask: str,
        sms_runtime: Any,
        performance_runtime: Any,
        notifications: Any,
        migrate_email_timeout: Callable[[Any], tuple[dict[str, Any], bool]],
        read_local_config: Callable[[], dict[str, Any]],
        online_mailbox_default_url: str,
        email_timeout_strategy_version: int,
        sms_min_price_default: Any,
        int_value: Callable[..., int],
        as_enabled: Callable[..., bool],
        clamp_sms_max_price: Callable[[Any], Any],
        migrate_email_proxy_scope: Callable[[Any], tuple[dict[str, Any], bool]] | None = None,
    ) -> None:
        self.clean = clean
        self.secret_mask = str(secret_mask)
        self.sms_runtime = sms_runtime
        self.performance_runtime = performance_runtime
        self.notifications = notifications
        self.migrate_email_timeout = migrate_email_timeout
        self.migrate_email_proxy_scope = migrate_email_proxy_scope or make_email_proxy_scope_migrator()
        self.read_local_config = read_local_config
        self.online_mailbox_default_url = online_mailbox_default_url
        self.email_timeout_strategy_version = int(email_timeout_strategy_version)
        self.sms_min_price_default = sms_min_price_default
        self.int_value = int_value
        self.as_enabled = as_enabled
        self.clamp_sms_max_price = clamp_sms_max_price

    def local_secret(self, value: Any, fallback: Any = "") -> str:
        text = str(value or "")
        if not self.clean(text) or text == self.secret_mask:
            return str(fallback or "")
        return text

    def sms_provider_pools_from_config(self, data: Any) -> list[dict[str, Any]]:
        value = data if isinstance(data, dict) else {}
        return self.sms_runtime.normalize_sms_provider_pools(
            value.get("sms_provider_pools"),
            legacy_provider=value.get("sms_provider") or "smsbower",
            legacy_keys=value.get("sms_api_keys"),
            legacy_key=value.get("sms_api_key"),
        )

    def sms_keys_from_config(self, data: Any) -> list[str]:
        return self.sms_runtime.flatten_sms_provider_keys(
            self.sms_provider_pools_from_config(data)
        )

    def resolve_sms_provider_pools(
        self,
        data: Any,
        existing: Any = None,
    ) -> list[dict[str, Any]]:
        value = data if isinstance(data, dict) else {}
        previous = self.sms_provider_pools_from_config(existing or {})
        previous_by_provider = {
            str(pool.get("provider") or ""): pool
            for pool in previous
        }
        if "sms_provider_pools" not in value:
            if "sms_api_keys" not in value and "sms_api_key" not in value:
                return previous
            keys = self.resolve_sms_keys(value, existing, _skip_pools=True)
            return self.sms_runtime.normalize_sms_provider_pools(
                None,
                legacy_provider=(
                    value.get("sms_provider")
                    or (existing or {}).get("sms_provider")
                    or "smsbower"
                ),
                legacy_keys=keys,
            )

        raw_pools = value.get("sms_provider_pools")
        rows = raw_pools if isinstance(raw_pools, (list, tuple)) else []
        resolved = []
        for raw in rows:
            if not isinstance(raw, dict):
                continue
            provider = self.sms_runtime.normalize_sms_provider_name(raw.get("provider"))
            if not provider:
                continue
            prior = previous_by_provider.get(provider, {})
            prior_keys = self.sms_runtime.normalize_sms_keys(prior.get("api_keys"))
            incoming_keys = raw.get("api_keys") if "api_keys" in raw else prior_keys
            key_rows = incoming_keys if isinstance(incoming_keys, (list, tuple)) else [incoming_keys]
            keys = []
            for index, row in enumerate(key_rows):
                text = str(row or "").strip()
                if text == self.secret_mask:
                    text = prior_keys[index] if index < len(prior_keys) else ""
                keys.append(text)
            resolved.append(
                {
                    "provider": provider,
                    "enabled": self.as_enabled(
                        raw.get("enabled"),
                        self.as_enabled(prior.get("enabled"), True),
                    ),
                    "api_keys": self.sms_runtime.normalize_sms_keys(keys),
                    "service": str(
                        raw.get("service")
                        or prior.get("service")
                        or self.sms_runtime.SMS_PROVIDER_DEFAULT_SERVICES.get(provider, "dr")
                    ).strip(),
                }
            )
        return self.sms_runtime.normalize_sms_provider_pools(resolved)

    def resolve_sms_keys(
        self,
        data: Any,
        existing: Any = None,
        _skip_pools: bool = False,
    ) -> list[str]:
        value = data if isinstance(data, dict) else {}
        if not _skip_pools and "sms_provider_pools" in value:
            return self.sms_runtime.flatten_sms_provider_keys(
                self.resolve_sms_provider_pools(value, existing)
            )
        previous_pools = self.sms_provider_pools_from_config(existing or {})
        previous = self.sms_runtime.legacy_sms_provider_keys(
            previous_pools,
            (existing or {}).get("sms_provider") or "smsbower",
        )
        if "sms_api_keys" in value:
            raw = value.get("sms_api_keys")
            rows = raw if isinstance(raw, (list, tuple)) else [raw]
            resolved = []
            for index, row in enumerate(rows):
                text = str(row or "").strip()
                if text == self.secret_mask:
                    text = previous[index] if index < len(previous) else ""
                resolved.append(text)
            return self.sms_runtime.normalize_sms_keys(resolved)
        if "sms_api_key" in value:
            text = str(value.get("sms_api_key") or "").strip()
            if text == self.secret_mask:
                return previous[:1]
            return self.sms_runtime.normalize_sms_keys(text)
        return previous

    def local_config_secret(self, secret_id: Any) -> Any:
        local = self.read_local_config()
        sub2api = dict(local.get("sub2api") or {})
        email_notification = dict(local.get("email_notification") or {})
        online_mailbox = dict(local.get("online_mailbox") or {})
        sms_keys = self.sms_keys_from_config(local)
        sms_pools = self.sms_provider_pools_from_config(local)
        values = {
            "sms_provider_pools": sms_pools,
            "sms_api_keys": sms_keys,
            "sms_api_key": sms_keys[0] if sms_keys else "",
            "sub2_password": sub2api.get("password") or "",
            "notification_email_password": email_notification.get("password") or "",
            "online_mailbox_api_token": online_mailbox.get("api_token") or "",
            "proxy": local.get("proxy") or "",
        }
        return values.get(str(secret_id or ""), "")

    def local_config_from_runtime(
        self,
        data: Any,
        existing: Any = None,
    ) -> dict[str, Any]:
        raw_data = dict(data or {}) if isinstance(data, dict) else {}
        existing = dict(existing or {})
        # Preserve a post-migration manual choice when a legacy client sends a
        # partial payload without the strategy marker or proxy scope block.
        if "email_proxy_scope_strategy_version" not in raw_data:
            prior_version = existing.get("email_proxy_scope_strategy_version")
            if prior_version is not None:
                raw_data["email_proxy_scope_strategy_version"] = prior_version
        if "proxy_scope" not in raw_data and isinstance(existing.get("proxy_scope"), dict):
            raw_data["proxy_scope"] = copy.deepcopy(existing["proxy_scope"])
        raw_data, _proxy_scope_migrated = self.migrate_email_proxy_scope(raw_data)
        sms_pools = self.resolve_sms_provider_pools(raw_data, existing)
        sms_keys = self.sms_runtime.legacy_sms_provider_keys(
            sms_pools,
            raw_data.get("sms_provider") or "smsbower",
        )
        raw_data["sms_provider_pools"] = sms_pools
        raw_data["sms_api_keys"] = sms_keys
        raw_data["sms_api_key"] = sms_keys[0] if sms_keys else ""
        data, _migrated = self.sms_runtime.migrate_performance_config(raw_data)
        data = self.performance_runtime.normalize_feature_flags(data)
        data, _timeout_migrated = self.migrate_email_timeout(data)
        sub2api = dict(data.get("sub2api") or {})
        existing_sub2api = dict(existing.get("sub2api") or {})
        email_notification = dict(data.get("email_notification") or {})
        existing_email_notification = dict(existing.get("email_notification") or {})
        online_mailbox = dict(data.get("online_mailbox") or {})
        existing_online_mailbox = dict(existing.get("online_mailbox") or {})
        resolved_email_notification = self.notifications.normalize_email_notification(
            self.merge_email_notification(existing_email_notification, email_notification)
        )
        resolved_email_notification["password"] = self.local_secret(
            email_notification.get("password"),
            existing_email_notification.get("password"),
        ).strip()
        allow_free_plan_sms_binding = self.as_enabled(
            data.get("allow_free_plan_sms_binding")
            if "allow_free_plan_sms_binding" in data
            else existing.get("allow_free_plan_sms_binding"),
            False,
        )
        result = {
            "performance_policy_version": self.sms_runtime.PERFORMANCE_POLICY_VERSION,
            "email_timeout_strategy_version": self.email_timeout_strategy_version,
            "allow_free_plan_sms_binding": allow_free_plan_sms_binding,
            "sms_provider_pools": sms_pools,
            "sms_provider": (
                str(sms_pools[0].get("provider") or "smsbower")
                if sms_pools
                else "smsbower"
            ),
            "sms_api_keys": sms_keys,
            "sub2api": {
                "url": str(sub2api.get("url") or "").strip(),
                "email": str(sub2api.get("email") or "").strip(),
                "password": self.local_secret(
                    sub2api.get("password"),
                    existing_sub2api.get("password"),
                ),
                "group": str(sub2api.get("group") or "").strip(),
            },
            "online_mailbox": {
                "base_url": str(
                    online_mailbox.get("base_url")
                    or existing_online_mailbox.get("base_url")
                    or self.online_mailbox_default_url
                ).strip(),
                "api_token": self.local_secret(
                    online_mailbox.get("api_token"),
                    existing_online_mailbox.get("api_token"),
                ).strip(),
            },
            "email_notification": resolved_email_notification,
        }
        if "proxy" in data or "proxy" in existing:
            result["proxy"] = self.local_secret(
                data.get("proxy"), existing.get("proxy")
            ).strip()
        for key in (
            "proxy_scope",
            "email_proxy_scope_strategy_version",
            "target_count",
            "concurrency",
            "node_concurrency",
            "auto_email_login_concurrency",
            "phone_submission_concurrency",
            "node_timeout",
            "auth_session_retries",
            "email_code_timeout",
            "email_otp_verify_attempts",
            "email_otp_resend_on_retry",
            "sms_min_price",
            "max_price",
            "sms_timeout",
            "phone_max_attempts",
            "phone_attempts_per_provider",
            "phone_session_cycle_seconds",
            "sms_quality_optimization",
            "adaptive_task_concurrency",
            "task_inflight_optimization",
            "task_inflight_limit",
            "openai_connectivity_guard",
            "phone_binding_compatibility",
            "mailbox_result_index_cache",
            "protocol_concurrency_ceiling",
            "dynamic_auth_challenges",
        ):
            if key in data:
                result[key] = copy.deepcopy(data[key])
            elif key in existing:
                result[key] = copy.deepcopy(existing[key])
        return result

    def merge_nonempty(self, base: Any, override: Any) -> dict[str, Any]:
        result = dict(base or {})
        for key, value in dict(override or {}).items():
            if self.clean(value) and value != self.secret_mask:
                result[key] = value
        return result

    def merge_email_notification(self, base: Any, override: Any) -> dict[str, Any]:
        previous = copy.deepcopy(dict(base or {}))
        incoming = copy.deepcopy(dict(override or {}))
        events = {
            **dict(previous.get("events") or {}),
            **dict(incoming.get("events") or {}),
        }
        result = {**previous, **incoming}
        result["events"] = events
        result["password"] = self.local_secret(
            incoming.get("password"), previous.get("password")
        )
        return result

    def merge_local_config(self, data: Any) -> dict[str, Any]:
        patched = dict(data or {})
        local = self.read_local_config()
        if "email_proxy_scope_strategy_version" not in patched:
            prior_version = local.get("email_proxy_scope_strategy_version")
            if prior_version is not None:
                patched["email_proxy_scope_strategy_version"] = prior_version
        if "proxy_scope" not in patched and isinstance(local.get("proxy_scope"), dict):
            patched["proxy_scope"] = copy.deepcopy(local["proxy_scope"])
        patched, _proxy_scope_migrated = self.migrate_email_proxy_scope(patched)
        sms_pools = self.resolve_sms_provider_pools(patched, local)
        sms_keys = self.sms_runtime.legacy_sms_provider_keys(
            sms_pools,
            patched.get("sms_provider") or "smsbower",
        )
        patched["sms_provider_pools"] = sms_pools
        patched["sms_provider"] = (
            str(sms_pools[0].get("provider") or "smsbower")
            if sms_pools
            else "smsbower"
        )
        patched["sms_api_keys"] = sms_keys
        patched["sms_api_key"] = sms_keys[0] if sms_keys else ""
        patched["proxy"] = self.local_secret(
            patched.get("proxy"), local.get("proxy")
        )
        if isinstance(local.get("sub2api"), dict):
            patched["sub2api"] = self.merge_nonempty(
                local.get("sub2api") or {}, patched.get("sub2api") or {}
            )
        if isinstance(local.get("email_notification"), dict):
            patched["email_notification"] = self.merge_email_notification(
                local.get("email_notification") or {},
                patched.get("email_notification") or {},
            )
        if isinstance(local.get("online_mailbox"), dict):
            patched["online_mailbox"] = self.merge_nonempty(
                local.get("online_mailbox") or {},
                patched.get("online_mailbox") or {},
            )
        return patched

    def apply_server_defaults(self, data: Any) -> dict[str, Any]:
        patched = self.merge_local_config(dict(data or {}))
        patched, _migrated = self.sms_runtime.migrate_performance_config(patched)
        patched = self.performance_runtime.normalize_feature_flags(patched)
        patched, _timeout_migrated = self.migrate_email_timeout(patched)
        patched, _proxy_scope_migrated = self.migrate_email_proxy_scope(patched)
        patched["dynamic_auth_challenges"] = self.as_enabled(
            patched.get("dynamic_auth_challenges"), True
        )
        patched["openai_connectivity_guard"] = self.as_enabled(
            patched.get("openai_connectivity_guard"), True
        )
        patched["allow_free_plan_sms_binding"] = self.as_enabled(
            patched.get("allow_free_plan_sms_binding"), False
        )
        patched["protocol_concurrency_ceiling"] = self.int_value(
            patched.get("protocol_concurrency_ceiling"),
            12,
            minimum=8,
            maximum=15,
        )
        if patched.get("sms_provider") == "localpool":
            patched["sms_provider"] = "smsbower"
        patched["email_mode"] = "auto"
        patched["sms_mode"] = "smart"
        patched["country"] = ""
        patched["provider_ids"] = ""
        patched.pop("manual_pool_content", None)
        patched.pop("nvtoken", None)
        patched.pop("nvtoken_upload", None)
        patched.pop("pixel_upload_enabled", None)
        patched.pop("nv_import", None)
        patched["sub2api"] = dict(patched.get("sub2api") or {})
        patched["email_notification"] = self.notifications.validate_email_notification(
            patched.get("email_notification") or {}
        )
        if not self.clean(patched.get("proxy")):
            patched["proxy"] = "http://127.0.0.1:7897"
        if not self.clean(patched.get("concurrency")):
            patched["concurrency"] = "5"
        if not self.clean(patched.get("node_concurrency")):
            patched["node_concurrency"] = "5"
        patched["phone_submission_concurrency"] = self.int_value(
            patched.get("phone_submission_concurrency"),
            2,
            minimum=1,
            maximum=5,
        )
        if not self.clean(patched.get("sms_min_price")):
            patched["sms_min_price"] = str(self.sms_min_price_default)
        patched["max_price"] = self.clamp_sms_max_price(patched.get("max_price"))
        route_lease_seconds = (
            2 * self.int_value(
                patched.get("sms_timeout"), 30, minimum=5, maximum=300
            )
        ) + 20
        patched["sms_smart"] = {
            **dict(patched.get("sms_smart") or {}),
            "enabled": True,
            "countries": "",
            "preferred_countries": "",
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
        return patched

    def test_email_notification(self, data: Any) -> Any:
        local = self.local_config_from_runtime(data, self.read_local_config())
        config = dict(local.get("email_notification") or {})
        config["enabled"] = True
        return self.notifications.send_test_notification(config)


__all__ = [
    "EMAIL_PROXY_SCOPE_STRATEGY_VERSION",
    "LocalConfigRuntime",
    "atomic_write_private_json",
    "make_email_proxy_scope_migrator",
    "make_email_timeout_migrator",
    "read_store_config",
    "write_store_config",
]
