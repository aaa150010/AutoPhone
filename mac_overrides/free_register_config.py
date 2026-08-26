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
    "version": 7,
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
    "auto_set_2fa": True,
    # Automatic recovery is bounded to two additional attempts (three total
    # 2FA attempts including the initial enrollment). Direct manager callers
    # that omit this key retain the historical manual-only behavior.
    "twofa_auto_retry_attempts": 2,
    "proxy_probe_url": DEFAULT_PROXY_PROBE_URL,
    "proxy_default_scheme": "http",
    "proxy_socks5_dns_mode": "auto",
    "proxy_tls_verify": True,
    "proxy_tls_compat_fallback": True,
    "proxy_failure_threshold": 2,
    "proxy_quarantine_seconds": 600,
    "proxy_health_probe_ttl_seconds": 300,
    "proxy_retry_count": 1,
    "roxy_circuit_failure_threshold": 3,
    "roxy_circuit_recovery_seconds": 30,
    "proxy_selection": {
        "protocol": {"country": "", "group": ""},
        "roxybrowser": {"country": "", "group": ""},
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
    "roxybrowser": {
        "api_base": "http://127.0.0.1:50000",
        "api_key": "",
        "workspace_id": "",
        "project_id": "",
        "workspace_list_path": "/browser/workspace",
        "list_path": "/browser/list",
        "create_path": "/browser/create",
        "open_path": "/browser/open",
        "close_path": "/browser/close",
        "delete_path": "/browser/delete",
        "headless": True,
        "force_open": False,
        "keep_browser_open": False,
        "one_profile_per_account": True,
        "delete_profile_after_run": True,
        "random_os": True,
        "os_choices": ["Windows", "macOS"],
        "random_profile_name": True,
        "profile_name_prefix": "rb",
        "proxy_check_channel": "IPRust.io",
        "selenium_timeout": 90,
        "api_retries": 3,
        "api_retry_delay": 2.0,
        "humanize_delay": True,
        "humanize_factor": 1.0,
        "humanize_browser_actions": True,
        "existing_account_login": True,
        "post_registration_dwell_min": 18,
        "post_registration_dwell_max": 45,
        "cleanup_verify_timeout": 8,
        "cleanup_verify_interval": 0.25,
        "recover_cleanup_on_start": True,
    },
    "camoufox": {
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
        incoming = {key: copy.deepcopy(item) for key, item in dict(value or {}).items() if key in DEFAULT_FREE_CONFIG}
        base = _merge(DEFAULT_FREE_CONFIG, previous or {})
        if incoming.get("roxybrowser", {}).get("api_key") == SECRET_MASK:
            incoming = copy.deepcopy(incoming)
            incoming.setdefault("roxybrowser", {})["api_key"] = str(base["roxybrowser"].get("api_key") or "")
        if incoming.get("mailbox_proxy_url") == SECRET_MASK:
            incoming = copy.deepcopy(incoming)
            incoming["mailbox_proxy_url"] = str(base.get("mailbox_proxy_url") or DEFAULT_FREE_MAILBOX_PROXY)
        result = _merge(base, incoming)
        driver = str(result.get("driver") or "protocol").strip().lower()
        if driver not in {"protocol", "roxybrowser", "camoufox"}:
            raise FreeRegisterError("free_config", "保存 Free 配置", "Free 注册链路只能选择全协议、RoxyBrowser 或 Camoufox", retryable=False)
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
        # Free registration is required to finish with an enrolled TOTP. Keep
        # this server-owned invariant even when an older client submits false;
        # a failed enrollment remains ``twofa_pending`` and is never reported
        # as a successful account.
        result["auto_set_2fa"] = True
        result["twofa_auto_retry_attempts"] = _int(result.get("twofa_auto_retry_attempts"), 2, 0, 2)
        scheme = str(result.get("proxy_default_scheme") or "http").strip().lower()
        if scheme not in {"http", "https", "socks4", "socks5", "socks5h"}:
            scheme = "http"
        result["proxy_default_scheme"] = scheme
        dns_mode = str(result.get("proxy_socks5_dns_mode") or "auto").strip().lower()
        result["proxy_socks5_dns_mode"] = dns_mode if dns_mode in {"declared", "local", "remote", "auto"} else "auto"
        result["proxy_tls_verify"] = _as_bool(result.get("proxy_tls_verify"), True)
        result["proxy_tls_compat_fallback"] = _as_bool(result.get("proxy_tls_compat_fallback"), True)
        result["proxy_failure_threshold"] = _int(result.get("proxy_failure_threshold"), 2, 1, 10)
        result["proxy_quarantine_seconds"] = _int(result.get("proxy_quarantine_seconds"), 600, 30, 86400)
        result["proxy_health_probe_ttl_seconds"] = _int(result.get("proxy_health_probe_ttl_seconds"), 300, 0, 86400)
        result["proxy_retry_count"] = _int(result.get("proxy_retry_count"), 1, 0, 5)
        result["roxy_circuit_failure_threshold"] = _int(result.get("roxy_circuit_failure_threshold"), 3, 1, 10)
        result["roxy_circuit_recovery_seconds"] = _int(result.get("roxy_circuit_recovery_seconds"), 30, 0, 3600)
        selection = result.get("proxy_selection") if isinstance(result.get("proxy_selection"), Mapping) else {}
        normalized_selection: dict[str, dict[str, str]] = {}
        for driver in ("protocol", "roxybrowser", "camoufox"):
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

        roxy_defaults = DEFAULT_FREE_CONFIG["roxybrowser"]
        roxy = {key: copy.deepcopy(value) for key, value in dict(result.get("roxybrowser") or {}).items() if key in roxy_defaults}
        api_base = clean(roxy.get("api_base"), 500) or "http://127.0.0.1:50000"
        parsed_api = urlsplit(api_base)
        if parsed_api.scheme not in {"http", "https"} or not parsed_api.netloc:
            raise FreeRegisterError("free_config", "保存 Free 配置", "RoxyBrowser API 地址无效", retryable=False)
        roxy["api_base"] = api_base.rstrip("/")
        for key in ("api_key", "workspace_id", "project_id", "profile_name_prefix"):
            roxy[key] = clean(roxy.get(key), 500)
        for key in ("workspace_list_path", "list_path", "create_path", "open_path", "close_path", "delete_path", "proxy_check_channel"):
            roxy[key] = clean(roxy.get(key), 500) or str(DEFAULT_FREE_CONFIG["roxybrowser"][key])
        for key in (
            "headless", "force_open", "keep_browser_open", "one_profile_per_account", "delete_profile_after_run",
            "random_os", "random_profile_name", "humanize_delay", "humanize_browser_actions", "existing_account_login",
        ):
            roxy[key] = _as_bool(roxy.get(key), bool(DEFAULT_FREE_CONFIG["roxybrowser"][key]))
        # Older stores always persisted the old ``headless=false`` default, so
        # presence alone cannot distinguish it from an explicit user choice.
        # Migrate every pre-v5 store once; after v5 the user's advanced toggle
        # is authoritative and an explicit false value is preserved.
        if source_version < 5:
            roxy["headless"] = True
        roxy["force_open"] = False
        choices = roxy.get("os_choices")
        if isinstance(choices, str):
            choices = [item.strip() for item in choices.replace(";", ",").split(",") if item.strip()]
        valid_os = [str(item) for item in (choices or []) if str(item) in {"Windows", "macOS", "Linux", "IOS", "Android"}]
        roxy["os_choices"] = valid_os or ["Windows", "macOS"]
        roxy["selenium_timeout"] = _int(roxy.get("selenium_timeout"), 90, 10, 300)
        roxy["api_retries"] = _int(roxy.get("api_retries"), 3, 1, 5)
        roxy["api_retry_delay"] = _float(roxy.get("api_retry_delay"), 2.0, 0.25, 15.0)
        roxy["cleanup_verify_timeout"] = _float(roxy.get("cleanup_verify_timeout"), 8.0, 0.5, 60.0)
        roxy["cleanup_verify_interval"] = _float(roxy.get("cleanup_verify_interval"), 0.25, 0.05, 5.0)
        roxy["recover_cleanup_on_start"] = _as_bool(roxy.get("recover_cleanup_on_start"), True)
        roxy["humanize_factor"] = _float(roxy.get("humanize_factor"), 1.0, 0.1, 5.0)
        roxy["post_registration_dwell_min"] = _int(roxy.get("post_registration_dwell_min"), 18, 0, 300)
        roxy["post_registration_dwell_max"] = _int(roxy.get("post_registration_dwell_max"), 45, roxy["post_registration_dwell_min"], 600)
        if not roxy["profile_name_prefix"]:
            roxy["profile_name_prefix"] = "rb"
        result["roxybrowser"] = roxy
        # Keep the old shape for API compatibility, but always return empty
        # classification values so they cannot influence allocation.
        camoufox_defaults = DEFAULT_FREE_CONFIG["camoufox"]
        camoufox = {
            key: copy.deepcopy(value)
            for key, value in dict(result.get("camoufox") or {}).items()
            if key in camoufox_defaults
        }
        for key in ("headless", "block_images", "existing_account_login"):
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
            "roxybrowser": {"country": "", "group": ""},
            "camoufox": {"country": "", "group": ""},
        }
        # v5 carried the old classified-proxy policy.  Keep its first
        # migration marker at v6 so existing stores can be upgraded in two
        # atomic, observable steps; v6 and newer stores use the v7 Camoufox
        # schema on the next normalization.
        result["version"] = 6 if source_version < 6 else 7
        return result

    def load(self) -> dict[str, Any]:
        with self._lock:
            try:
                value = json.loads(self.path.read_text(encoding="utf-8"))
            except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError):
                value = {}
            source = value if isinstance(value, Mapping) else {}
            normalized = self.normalize(source)
            # Persist one-time schema/policy migrations. v6 files must be
            # written back as v7 so the normalized Camoufox schema is durable.
            try:
                source_version = int(source.get("version") or 0)
            except (TypeError, ValueError):
                source_version = 0
            needs_policy_migration = (
                self.path.exists()
                and (
                    source_version < 7
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
        roxy = dict(value.get("roxybrowser") or {})
        roxy["api_key"] = SECRET_MASK if clean(roxy.get("api_key")) else ""
        value["roxybrowser"] = roxy
        mailbox_proxy = str(value.get("mailbox_proxy_url") or "")
        try:
            parsed_mailbox_proxy = urlsplit(mailbox_proxy)
        except ValueError:
            parsed_mailbox_proxy = None
        if parsed_mailbox_proxy is not None and (parsed_mailbox_proxy.username or parsed_mailbox_proxy.password):
            value["mailbox_proxy_url"] = SECRET_MASK
        return value

    def secret(self, secret_id: str) -> str:
        if secret_id not in {"roxy_api_key", "mailbox_proxy_url"}:
            raise FreeRegisterError("free_config_secret", "读取 Free 配置密钥", "Free 配置密钥类型无效", retryable=False)
        value = self.load()
        if secret_id == "mailbox_proxy_url":
            return str(value.get("mailbox_proxy_url") or "")
        return str(value.get("roxybrowser", {}).get("api_key") or "")

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
