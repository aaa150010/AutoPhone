"""Independent configuration and one-time migration for Free registration."""

from __future__ import annotations

import copy
import json
from pathlib import Path
import re
import shutil
import threading
import os
from typing import Any, Mapping
from urllib.parse import urlsplit

try:
    from .free_register_common import FreeRegisterError, SECRET_MASK, atomic_write, clean
    from .free_proxy_store import DEFAULT_PROXY_PROBE_URL, normalize_probe_url
    from .mailbox_otp_service import DEFAULT_FREE_MAILBOX_PROXY, MailboxOtpError, normalize_network_policy
except ImportError:
    from free_register_common import FreeRegisterError, SECRET_MASK, atomic_write, clean  # type: ignore[no-redef]
    from free_proxy_store import DEFAULT_PROXY_PROBE_URL, normalize_probe_url  # type: ignore[no-redef]
    from mailbox_otp_service import (  # type: ignore[no-redef]
        DEFAULT_FREE_MAILBOX_PROXY, MailboxOtpError, normalize_network_policy,
    )


FREE_LEGACY_CONFIG_KEYS = frozenset({
    "free_concurrency",
    "free_target_count",
    "free_proxy_pool_content",
    "free_proxy_probe_url",
    "free_register_password",
    "free_pool_content",
})

DEFAULT_FREE_CONFIG: dict[str, Any] = {
    "version": 9,
    "driver": "protocol",
    "flow_profile": "reference_20260823",
    "proxy_allocation_mode": "healthy_random",
    "target_count": 1,
    "concurrency": 3,
    "email_code_timeout": 90,
    "mailbox_network_mode": "local_proxy",
    "mailbox_proxy_url": DEFAULT_FREE_MAILBOX_PROXY,
    "mailbox_request_retries": 3,
    "mailbox_retry_backoff_seconds": 1.0,
    "remail": {
        "enabled": False,
        "base_url": "https://remail.aishop6.com",
        "api_key": "",
        "project_id": "",
        "supply_policy": "private_first",
        "request_timeout_seconds": 20,
        "catalog_cache_seconds": 60,
        "order_sync_enabled": False,
        "order_sync_interval_minutes": 30,
        "auto_import_new_purchase_orders": False,
    },
    # One password is shared by the signup password page and the optional
    # post-registration password continuation. It is masked by ``public``.
    "account_password": "Aa150010150010",
    # Password setup is opt-in. Keep the historical 2FA default enabled while
    # allowing callers to explicitly disable either post-registration step.
    "auto_set_password": False,
    "auto_set_2fa": True,
    # Automatic recovery is bounded to two additional attempts (three total
    # 2FA attempts including the initial enrollment). Direct manager callers
    # that omit this key retain the historical manual-only behavior.
    "twofa_auto_retry_attempts": 2,
    "proxy_probe_url": DEFAULT_PROXY_PROBE_URL,
    "proxy_default_scheme": "socks5",
    "proxy_socks5_dns_mode": "remote",
    "proxy_tls_verify": True,
    "proxy_tls_compat_fallback": True,
    "proxy_failure_threshold": 2,
    "proxy_quarantine_seconds": 600,
    "proxy_health_probe_ttl_seconds": 300,
    "proxy_retry_count": 1,
    "proxy_selection": {
        "protocol": {"country": "", "group": ""},
        "camoufox": {"country": "", "group": ""},
    },
    "protocol": {
        "node_runner": "",
        "sentinel_version": "20260219f9f6",
        "sentinel_timeout": 90,
        "network_timeout": 20,
        "network_preflight_retries": 3,
        "security_challenge_wait_seconds": 60,
        "anonymous_warmup": True,
        "authenticated_warmup": True,
        "geo_probe_url": "https://ipwho.is/",
    },
    "camoufox": {
        # Debug mode intentionally defaults on so a failed browser task leaves
        # a visible page available for diagnosis.  ``headless`` is kept as the
        # user's persisted preference; the runtime derives an effective headed
        # value while debug mode is enabled and restores this preference when
        # debug mode is turned off.
        "debug_mode": True,
        "headless": True,
        "pool_size": 2,
        "max_contexts_per_browser": 3,
        "context_start_interval_ms": 175,
        "startup_concurrency": 4,
        "block_images": True,
        "registration_timeout_seconds": 600,
        "context_close_timeout_seconds": 15,
        "browser_recycle_timeout_seconds": 45,
        "browser_recycle_drain_timeout_seconds": 20,
        "max_registrations_per_browser": 12,
        "browser_launch_attempts": 3,
        "existing_account_login": True,
    },
}

# The previous implementation shipped this value as a code-level default.
# Treat it as a migration marker only; an explicitly different user password
# must remain untouched.
LEGACY_DEFAULT_FREE_PASSWORD = "Aa150010@150010"


def _merge(base: Mapping[str, Any], incoming: Mapping[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(dict(base))
    for key, value in incoming.items():
        if isinstance(value, Mapping) and isinstance(result.get(key), Mapping):
            result[key] = _merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def _as_bool(value: Any, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    normalized = str(value or "").strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    return default


def _int(value: Any, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(maximum, parsed))


def _float(value: Any, default: float, minimum: float, maximum: float) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(maximum, parsed))


class FreeConfigStore:
    def __init__(self, data_dir: str | Path) -> None:
        self.data_dir = Path(data_dir).expanduser().resolve()
        self.path = self.data_dir / "config.json"
        self.migration_path = self.data_dir / "migration.json"
        self.proxy_policy_migration_path = self.data_dir / "single_pool_migration.json"
        self.log_path = self.data_dir / "logs.json"
        self.lock_path = self.data_dir / "runtime.lock"
        self._lock = threading.RLock()

    def normalize(self, value: Mapping[str, Any] | None, *, previous: Mapping[str, Any] | None = None) -> dict[str, Any]:
        source_version = _int(
            (value or {}).get("version", (previous or {}).get("version")),
            0, 0, 10_000,
        )
        raw_value = dict(value or {})
        # The old ordinary-config key is no longer persisted there, but accept
        # it during the one-time migration so a user's chosen password is not
        # silently replaced by the new default.
        if "account_password" not in raw_value and "free_register_password" in raw_value:
            raw_value["account_password"] = raw_value.get("free_register_password")
        incoming = {key: copy.deepcopy(item) for key, item in raw_value.items() if key in DEFAULT_FREE_CONFIG}
        # v7 and older stores used HTTP plus automatic SOCKS5 DNS selection as
        # their defaults. Migrate only those exact legacy values; current
        # stores keep every explicit protocol/DNS choice unchanged.
        if source_version < 8:
            if str(incoming.get("proxy_default_scheme") or "").strip().lower() == "http":
                incoming["proxy_default_scheme"] = "socks5"
            if str(incoming.get("proxy_socks5_dns_mode") or "").strip().lower() == "auto":
                incoming["proxy_socks5_dns_mode"] = "remote"
        # v8 predates the Camoufox debug toggle. Treat a missing toggle as the
        # new default (enabled), while preserving an explicit value from a
        # newer or manually edited store. Injecting this into ``incoming`` is
        # important when a caller supplies ``previous``: an older snapshot
        # must not allow its stale debug value to override the migration.
        if source_version < 9:
            legacy_camoufox = incoming.get("camoufox")
            if not isinstance(legacy_camoufox, Mapping):
                legacy_camoufox = {}
            elif not isinstance(legacy_camoufox, dict):
                legacy_camoufox = dict(legacy_camoufox)
            if "debug_mode" not in legacy_camoufox:
                legacy_camoufox["debug_mode"] = True
            incoming["camoufox"] = legacy_camoufox
        base = _merge(DEFAULT_FREE_CONFIG, previous or {})
        if incoming.get("mailbox_proxy_url") == SECRET_MASK:
            incoming = copy.deepcopy(incoming)
            incoming["mailbox_proxy_url"] = str(base.get("mailbox_proxy_url") or DEFAULT_FREE_MAILBOX_PROXY)
        result = _merge(base, incoming)
        # Do not carry the removed browser integration back into the persisted
        # configuration. Legacy values are accepted only long enough to select
        # the protocol driver during migration.
        result.pop("roxybrowser", None)
        result.pop("roxy_circuit_failure_threshold", None)
        result.pop("roxy_circuit_recovery_seconds", None)
        driver = str(result.get("driver") or "protocol").strip().lower()
        if driver == "roxybrowser":
            driver = "protocol"
        if driver not in {"protocol", "camoufox"}:
            raise FreeRegisterError("free_config", "保存 Free 配置", "Free 注册链路只能选择全协议或 Camoufox", retryable=False)
        result["driver"] = driver
        flow_profile = str(result.get("flow_profile") or "reference_20260823").strip().lower()
        result["flow_profile"] = flow_profile if flow_profile in {"reference_20260823", "legacy"} else "reference_20260823"
        # The Free pool is shared and random, regardless of a legacy value.
        result["proxy_allocation_mode"] = "healthy_random"
        result["target_count"] = _int(result.get("target_count"), 1, 1, 200)
        result["concurrency"] = _int(result.get("concurrency"), 3, 1, 16)
        result["email_code_timeout"] = _int(result.get("email_code_timeout"), 90, 10, 600)
        try:
            mailbox_policy = normalize_network_policy(
                mode=result.get("mailbox_network_mode"),
                proxy_url=result.get("mailbox_proxy_url"),
                retries=result.get("mailbox_request_retries"),
                backoff_seconds=result.get("mailbox_retry_backoff_seconds"),
                request_timeout_seconds=min(15, result["email_code_timeout"]),
            )
        except MailboxOtpError as exc:
            raise FreeRegisterError(
                "free_config", "保存 Free 配置", str(exc),
                error_code=str(exc.code or "free_mailbox_network_invalid"), retryable=False,
            ) from exc
        result["mailbox_network_mode"] = mailbox_policy.mode
        result["mailbox_proxy_url"] = mailbox_policy.proxy_url
        result["mailbox_request_retries"] = mailbox_policy.retries
        result["mailbox_retry_backoff_seconds"] = mailbox_policy.backoff_seconds
        remail_defaults = DEFAULT_FREE_CONFIG["remail"]
        remail_incoming = result.get("remail") if isinstance(result.get("remail"), Mapping) else {}
        remail = _merge(remail_defaults, remail_incoming)
        previous_remail = base.get("remail") if isinstance(base.get("remail"), Mapping) else {}
        if remail.get("api_key") == SECRET_MASK:
            remail["api_key"] = str(previous_remail.get("api_key") or "")
        remail["enabled"] = _as_bool(remail.get("enabled"), False)
        remail["base_url"] = clean(remail.get("base_url"), 300) or remail_defaults["base_url"]
        remail["api_key"] = clean(remail.get("api_key"), 300)
        remail["project_id"] = clean(remail.get("project_id"), 80)
        remail["supply_policy"] = str(remail.get("supply_policy") or "private_first").strip().lower()
        if remail["supply_policy"] not in {"private_first", "public_only"}:
            remail["supply_policy"] = "private_first"
        remail["request_timeout_seconds"] = _int(remail.get("request_timeout_seconds"), 20, 3, 120)
        remail["catalog_cache_seconds"] = _int(remail.get("catalog_cache_seconds"), 60, 0, 3600)
        remail["order_sync_enabled"] = _as_bool(remail.get("order_sync_enabled"), False)
        remail["order_sync_interval_minutes"] = _int(remail.get("order_sync_interval_minutes"), 30, 1, 1440)
        remail["auto_import_new_purchase_orders"] = _as_bool(remail.get("auto_import_new_purchase_orders"), False)
        result["remail"] = remail
        account_password = clean(result.get("account_password"), 256)
        if account_password == SECRET_MASK:
            account_password = clean(base.get("account_password"), 256)
        if account_password == LEGACY_DEFAULT_FREE_PASSWORD:
            account_password = str(DEFAULT_FREE_CONFIG["account_password"])
        result["account_password"] = account_password or str(DEFAULT_FREE_CONFIG["account_password"])
        # Each post-registration security step is independently configurable.
        # In particular, preserve an explicit false instead of restoring the
        # former server-owned 2FA invariant.
        result["auto_set_password"] = _as_bool(
            result.get("auto_set_password"), bool(DEFAULT_FREE_CONFIG["auto_set_password"])
        )
        result["auto_set_2fa"] = _as_bool(
            result.get("auto_set_2fa"), bool(DEFAULT_FREE_CONFIG["auto_set_2fa"])
        )
        result["twofa_auto_retry_attempts"] = _int(result.get("twofa_auto_retry_attempts"), 2, 0, 2)
        scheme = str(result.get("proxy_default_scheme") or DEFAULT_FREE_CONFIG["proxy_default_scheme"]).strip().lower()
        if scheme not in {"http", "https", "socks4", "socks5", "socks5h"}:
            scheme = DEFAULT_FREE_CONFIG["proxy_default_scheme"]
        result["proxy_default_scheme"] = scheme
        dns_mode = str(result.get("proxy_socks5_dns_mode") or DEFAULT_FREE_CONFIG["proxy_socks5_dns_mode"]).strip().lower()
        result["proxy_socks5_dns_mode"] = dns_mode if dns_mode in {"declared", "local", "remote", "auto"} else DEFAULT_FREE_CONFIG["proxy_socks5_dns_mode"]
        result["proxy_tls_verify"] = _as_bool(result.get("proxy_tls_verify"), True)
        result["proxy_tls_compat_fallback"] = _as_bool(result.get("proxy_tls_compat_fallback"), True)
        result["proxy_failure_threshold"] = _int(result.get("proxy_failure_threshold"), 2, 1, 10)
        result["proxy_quarantine_seconds"] = _int(result.get("proxy_quarantine_seconds"), 600, 30, 86400)
        result["proxy_health_probe_ttl_seconds"] = _int(result.get("proxy_health_probe_ttl_seconds"), 300, 0, 86400)
        result["proxy_retry_count"] = _int(result.get("proxy_retry_count"), 1, 0, 5)
        selection = result.get("proxy_selection") if isinstance(result.get("proxy_selection"), Mapping) else {}
        normalized_selection: dict[str, dict[str, str]] = {}
        for driver in ("protocol", "camoufox"):
            item = selection.get(driver) if isinstance(selection.get(driver), Mapping) else {}
            country = clean(item.get("country"), 2).upper()
            if country and not re.fullmatch(r"[A-Z]{2}", country):
                country = ""
            normalized_selection[driver] = {
                "country": country,
                "group": clean(item.get("group"), 64),
            }
        result["proxy_selection"] = normalized_selection
        probe_url = normalize_probe_url(clean(result.get("proxy_probe_url"), 500) or DEFAULT_PROXY_PROBE_URL)
        parsed_probe = urlsplit(probe_url)
        if parsed_probe.scheme not in {"http", "https"} or not parsed_probe.netloc:
            raise FreeRegisterError("free_config", "保存 Free 配置", "Free 代理探测地址必须是 HTTP/HTTPS URL", retryable=False)
        result["proxy_probe_url"] = probe_url

        protocol_defaults = DEFAULT_FREE_CONFIG["protocol"]
        protocol = {key: copy.deepcopy(value) for key, value in dict(result.get("protocol") or {}).items() if key in protocol_defaults}
        protocol["node_runner"] = clean(protocol.get("node_runner"), 1000)
        sentinel_version = clean(protocol.get("sentinel_version"), 64)
        protocol["sentinel_version"] = sentinel_version or "20260219f9f6"
        protocol["sentinel_timeout"] = _int(protocol.get("sentinel_timeout"), 90, 10, 300)
        protocol["network_timeout"] = _int(protocol.get("network_timeout"), 20, 5, 60)
        protocol["network_preflight_retries"] = _int(protocol.get("network_preflight_retries"), 3, 1, 5)
        protocol["security_challenge_wait_seconds"] = _int(
            protocol.get("security_challenge_wait_seconds"), 60, 0, 60
        )
        protocol["anonymous_warmup"] = _as_bool(protocol.get("anonymous_warmup"), True)
        protocol["authenticated_warmup"] = _as_bool(protocol.get("authenticated_warmup"), True)
        geo_probe_url = clean(protocol.get("geo_probe_url"), 500)
        parsed_geo = urlsplit(geo_probe_url) if geo_probe_url else None
        protocol["geo_probe_url"] = geo_probe_url if parsed_geo and parsed_geo.scheme == "https" and parsed_geo.netloc else ""
        result["protocol"] = protocol

        # Keep the old shape for API compatibility, but always return empty
        # classification values so they cannot influence allocation.
        camoufox_defaults = DEFAULT_FREE_CONFIG["camoufox"]
        camoufox = {
            key: copy.deepcopy(value)
            for key, value in dict(result.get("camoufox") or {}).items()
            if key in camoufox_defaults
        }
        for key in ("debug_mode", "headless", "block_images", "existing_account_login"):
            camoufox[key] = _as_bool(camoufox.get(key), bool(camoufox_defaults[key]))
        camoufox["pool_size"] = _int(camoufox.get("pool_size"), 2, 1, 16)
        camoufox["max_contexts_per_browser"] = _int(camoufox.get("max_contexts_per_browser"), 3, 1, 32)
        camoufox["context_start_interval_ms"] = _int(camoufox.get("context_start_interval_ms"), 175, 0, 10_000)
        camoufox["startup_concurrency"] = _int(camoufox.get("startup_concurrency"), 4, 1, 64)
        camoufox["registration_timeout_seconds"] = _int(camoufox.get("registration_timeout_seconds"), 600, 60, 3600)
        camoufox["context_close_timeout_seconds"] = _int(camoufox.get("context_close_timeout_seconds"), 15, 1, 120)
        camoufox["browser_recycle_timeout_seconds"] = _int(camoufox.get("browser_recycle_timeout_seconds"), 45, 5, 300)
        camoufox["browser_recycle_drain_timeout_seconds"] = _int(camoufox.get("browser_recycle_drain_timeout_seconds"), 20, 1, 180)
        camoufox["max_registrations_per_browser"] = _int(camoufox.get("max_registrations_per_browser"), 12, 1, 1000)
        camoufox["browser_launch_attempts"] = _int(camoufox.get("browser_launch_attempts"), 3, 1, 10)
        result["camoufox"] = camoufox
        result["proxy_selection"] = {
            "protocol": {"country": "", "group": ""},
            "camoufox": {"country": "", "group": ""},
        }
        # Preserve the existing staged schema migrations and add v8 -> v9 for
        # the headed Camoufox debug default. A missing version is a fresh store
        # and receives the current schema immediately.
        if not value and not previous:
            result["version"] = DEFAULT_FREE_CONFIG["version"]
        elif source_version < 6:
            result["version"] = 6
        elif source_version < 7:
            result["version"] = 7
        elif source_version < 8:
            # Keep the pre-existing v7 -> v8 proxy-default migration as a
            # distinct persisted step. The next load performs v8 -> v9.
            result["version"] = 8
        else:
            result["version"] = DEFAULT_FREE_CONFIG["version"]
        return result

    def load(self) -> dict[str, Any]:
        with self._lock:
            try:
                value = json.loads(self.path.read_text(encoding="utf-8"))
            except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError):
                value = {}
            source = value if isinstance(value, Mapping) else {}
            normalized = self.normalize(source)
            # Persist one-time schema/policy migrations. Legacy files are
            # written back as v9 so the SOCKS5/remote and Camoufox debug
            # defaults are durable.
            try:
                source_version = int(source.get("version") or 0)
            except (TypeError, ValueError):
                source_version = 0
            legacy_roxy_config = (
                str(source.get("driver") or "").strip().lower() == "roxybrowser"
                or any(key in source for key in (
                    "roxybrowser",
                    "roxy_circuit_failure_threshold",
                    "roxy_circuit_recovery_seconds",
                ))
            )
            needs_policy_migration = (
                self.path.exists()
                and (
                    legacy_roxy_config
                    or source_version < DEFAULT_FREE_CONFIG["version"]
                    or "auto_set_password" not in source
                    or "auto_set_2fa" not in source
                    or "account_password" not in source
                    or not isinstance(source.get("camoufox"), Mapping)
                    or "debug_mode" not in source.get("camoufox", {})
                    or str(source.get("proxy_allocation_mode") or "").strip().lower() != "healthy_random"
                    or any(
                        isinstance(item, Mapping) and any(str(item.get(key) or "").strip() for key in ("country", "group"))
                        for item in ((source.get("proxy_selection") or {}).values() if isinstance(source.get("proxy_selection"), Mapping) else ())
                    )
                )
            )
            if needs_policy_migration:
                atomic_write(self.path, normalized)
            return normalized

    def save(self, value: Mapping[str, Any]) -> dict[str, Any]:
        with self._lock:
            normalized = self.normalize(value, previous=self.load())
            atomic_write(self.path, normalized)
            return normalized

    def public(self) -> dict[str, Any]:
        value = self.load()
        if str(value.get("account_password") or "").strip():
            value["account_password"] = SECRET_MASK
        mailbox_proxy = str(value.get("mailbox_proxy_url") or "")
        try:
            parsed_mailbox_proxy = urlsplit(mailbox_proxy)
        except ValueError:
            parsed_mailbox_proxy = None
        if parsed_mailbox_proxy is not None and (parsed_mailbox_proxy.username or parsed_mailbox_proxy.password):
            value["mailbox_proxy_url"] = SECRET_MASK
        remail = value.get("remail")
        if isinstance(remail, Mapping):
            remail = dict(remail)
            if str(remail.get("api_key") or "").strip():
                remail["api_key"] = SECRET_MASK
            value["remail"] = remail
        return value

    def secret(self, secret_id: str) -> str:
        if secret_id not in {"mailbox_proxy_url", "remail_api_key"}:
            raise FreeRegisterError("free_config_secret", "读取 Free 配置密钥", "Free 配置密钥类型无效", retryable=False)
        value = self.load()
        if secret_id == "mailbox_proxy_url":
            return str(value.get("mailbox_proxy_url") or "")
        if secret_id == "remail_api_key":
            remail = value.get("remail") if isinstance(value.get("remail"), Mapping) else {}
            return str(remail.get("api_key") or "")
        return ""

    def migrate_legacy(self, local_config: Mapping[str, Any] | None, legacy_data_dir: str | Path) -> dict[str, Any]:
        with self._lock:
            if self.migration_path.exists():
                return {"migrated": False, "reason": "already_migrated"}
            legacy = dict(local_config or {})
            initial = copy.deepcopy(DEFAULT_FREE_CONFIG)
            initial.update({
                "target_count": legacy.get("free_target_count", 0),
                "concurrency": legacy.get("free_concurrency", 3),
                "email_code_timeout": legacy.get("email_code_timeout", 90),
                "proxy_probe_url": legacy.get("free_proxy_probe_url", DEFAULT_PROXY_PROBE_URL),
            })
            if str(legacy.get("free_register_password") or "").strip():
                initial["account_password"] = legacy.get("free_register_password")
            initial["protocol"]["node_runner"] = str(legacy.get("codex_node_runner") or legacy.get("node_runner") or "")
            if not self.path.exists():
                atomic_write(self.path, self.normalize(initial))
            legacy_root = Path(legacy_data_dir).expanduser().resolve()
            copied: list[str] = []
            for name in ("free_mailbox_pool.txt", "free_mailbox_state.json", "free_proxy_pool.txt", "free_register_results"):
                source = legacy_root / name
                target = self.data_dir / name
                if not source.exists() or target.exists():
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                if source.is_dir():
                    shutil.copytree(source, target)
                    for directory, _dirnames, filenames in os.walk(target):
                        os.chmod(directory, 0o700)
                        for filename in filenames:
                            os.chmod(Path(directory) / filename, 0o600)
                else:
                    shutil.copy2(source, target)
                    os.chmod(target, 0o600)
                copied.append(name)
            proxy_content = str(legacy.get("free_proxy_pool_content") or "").strip()
            proxy_path = self.data_dir / "free_proxy_pool.txt"
            if proxy_content and not proxy_path.exists():
                proxy_path.parent.mkdir(parents=True, exist_ok=True)
                proxy_path.write_text(proxy_content.rstrip() + "\n", encoding="utf-8")
                os.chmod(proxy_path, 0o600)
                copied.append("free_proxy_pool_content")
            atomic_write(self.migration_path, {"version": 1, "completed": True, "copied": copied})
            return {"migrated": True, "copied": copied}

    @staticmethod
    def _clear_proxy_classification(value: Any) -> tuple[Any, bool]:
        changed = False
        if isinstance(value, list):
            output = []
            for item in value:
                normalized, item_changed = FreeConfigStore._clear_proxy_classification(item)
                output.append(normalized)
                changed = changed or item_changed
            return output, changed
        if not isinstance(value, Mapping):
            return value, False
        output: dict[str, Any] = {}
        for key, item in value.items():
            if key in {"proxy_country", "proxy_group"}:
                output[key] = ""
                changed = changed or bool(item)
                continue
            normalized, item_changed = FreeConfigStore._clear_proxy_classification(item)
            output[key] = normalized
            changed = changed or item_changed
        return output, changed

    def migrate_single_pool_state(self) -> dict[str, Any]:
        """Clear legacy proxy classifications from all Free persisted state."""
        with self._lock:
            try:
                marker = json.loads(self.proxy_policy_migration_path.read_text(encoding="utf-8"))
            except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError):
                marker = {}
            if isinstance(marker, Mapping) and int(marker.get("version") or 0) >= 1:
                return {"migrated": False, "reason": "already_migrated"}

            changed_files: list[str] = []

            def migrate_file(path: Path) -> None:
                try:
                    payload = json.loads(path.read_text(encoding="utf-8"))
                except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError):
                    return
                normalized, changed = self._clear_proxy_classification(payload)
                if path.name == "free_proxy_pool.json" and isinstance(normalized, Mapping):
                    rows = normalized.get("proxies")
                    if isinstance(rows, list):
                        cleaned_rows = []
                        pool_changed = False
                        for row in rows:
                            if not isinstance(row, Mapping):
                                cleaned_rows.append(row)
                                continue
                            cleaned = dict(row)
                            pool_changed = pool_changed or bool(cleaned.get("country") or cleaned.get("group"))
                            cleaned["country"] = ""
                            cleaned["group"] = ""
                            cleaned_rows.append(cleaned)
                        if pool_changed:
                            normalized = {**normalized, "proxies": cleaned_rows}
                            changed = True
                if changed:
                    atomic_write(path, normalized)
                    changed_files.append(str(path.relative_to(self.data_dir)))

            for name in (
                "free_proxy_pool.json",
                "free_mailbox_state.json",
                "tasks.json",
                "free_live_checks.json",
            ):
                migrate_file(self.data_dir / name)
            results_dir = self.data_dir / "free_register_results"
            if results_dir.is_dir():
                for path in sorted(results_dir.glob("*.json")):
                    migrate_file(path)
            atomic_write(
                self.proxy_policy_migration_path,
                {"version": 1, "completed": True, "changed_files": changed_files},
            )
            return {"migrated": True, "changed_files": changed_files}


def strip_legacy_free_config(value: Mapping[str, Any] | None) -> dict[str, Any]:
    result = dict(value or {})
    for key in FREE_LEGACY_CONFIG_KEYS:
        result.pop(key, None)
    return result


__all__ = [
    "DEFAULT_FREE_CONFIG", "FREE_LEGACY_CONFIG_KEYS", "FreeConfigStore", "strip_legacy_free_config",
]
