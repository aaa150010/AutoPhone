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
    "version": 4,
    "driver": "protocol",
    "target_count": 0,
    "concurrency": 3,
    "email_code_timeout": 90,
    "mailbox_network_mode": "local_proxy",
    "mailbox_proxy_url": DEFAULT_FREE_MAILBOX_PROXY,
    "mailbox_request_retries": 3,
    "mailbox_retry_backoff_seconds": 1.0,
    "auto_set_2fa": True,
    "proxy_probe_url": DEFAULT_PROXY_PROBE_URL,
    "proxy_default_scheme": "http",
    "proxy_tls_verify": True,
    "proxy_tls_compat_fallback": True,
    "proxy_failure_threshold": 2,
    "proxy_quarantine_seconds": 600,
    "proxy_retry_count": 1,
    "roxy_circuit_failure_threshold": 3,
    "roxy_circuit_recovery_seconds": 30,
    "proxy_selection": {
        "protocol": {"country": "", "group": ""},
        "roxybrowser": {"country": "", "group": ""},
    },
    "protocol": {
        "node_runner": "",
        "sentinel_timeout": 90,
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
        self.log_path = self.data_dir / "logs.json"
        self.lock_path = self.data_dir / "runtime.lock"
        self._lock = threading.RLock()

    def normalize(self, value: Mapping[str, Any] | None, *, previous: Mapping[str, Any] | None = None) -> dict[str, Any]:
        incoming = {key: copy.deepcopy(item) for key, item in dict(value or {}).items() if key in DEFAULT_FREE_CONFIG}
        base = _merge(DEFAULT_FREE_CONFIG, previous or {})
        # Version 2 used visible Roxy windows as its default. Treat that old
        # implicit value as the new headless default once, while preserving an
        # explicit choice after the configuration has been saved as version 3.
        try:
            legacy_version = int(dict(value or {}).get("version") or 0)
        except (TypeError, ValueError):
            legacy_version = 0
        incoming_roxy = value.get("roxybrowser") if isinstance(value, Mapping) else None
        if legacy_version < 3 and isinstance(incoming_roxy, Mapping) and incoming_roxy.get("headless") is not True:
            incoming = copy.deepcopy(incoming)
            incoming.setdefault("roxybrowser", {})["headless"] = True
        if incoming.get("roxybrowser", {}).get("api_key") == SECRET_MASK:
            incoming = copy.deepcopy(incoming)
            incoming.setdefault("roxybrowser", {})["api_key"] = str(base["roxybrowser"].get("api_key") or "")
        if incoming.get("mailbox_proxy_url") == SECRET_MASK:
            incoming = copy.deepcopy(incoming)
            incoming["mailbox_proxy_url"] = str(base.get("mailbox_proxy_url") or DEFAULT_FREE_MAILBOX_PROXY)
        result = _merge(base, incoming)
        driver = str(result.get("driver") or "protocol").strip().lower()
        if driver not in {"protocol", "roxybrowser"}:
            raise FreeRegisterError("free_config", "保存 Free 配置", "Free 注册链路只能选择全协议或 RoxyBrowser", retryable=False)
        result["driver"] = driver
        result["target_count"] = _int(result.get("target_count"), 0, 0, 10_000)
        result["concurrency"] = _int(result.get("concurrency"), 3, 1, 5)
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
        result["auto_set_2fa"] = _as_bool(result.get("auto_set_2fa"), True)
        scheme = str(result.get("proxy_default_scheme") or "http").strip().lower()
        if scheme not in {"http", "https", "socks4", "socks5", "socks5h"}:
            scheme = "http"
        result["proxy_default_scheme"] = scheme
        result["proxy_tls_verify"] = _as_bool(result.get("proxy_tls_verify"), True)
        result["proxy_tls_compat_fallback"] = _as_bool(result.get("proxy_tls_compat_fallback"), True)
        result["proxy_failure_threshold"] = _int(result.get("proxy_failure_threshold"), 2, 1, 10)
        result["proxy_quarantine_seconds"] = _int(result.get("proxy_quarantine_seconds"), 600, 30, 86400)
        result["proxy_retry_count"] = _int(result.get("proxy_retry_count"), 1, 0, 5)
        result["roxy_circuit_failure_threshold"] = _int(result.get("roxy_circuit_failure_threshold"), 3, 1, 10)
        result["roxy_circuit_recovery_seconds"] = _int(result.get("roxy_circuit_recovery_seconds"), 30, 0, 3600)
        selection = result.get("proxy_selection") if isinstance(result.get("proxy_selection"), Mapping) else {}
        normalized_selection: dict[str, dict[str, str]] = {}
        for driver in ("protocol", "roxybrowser"):
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
        protocol["sentinel_timeout"] = _int(protocol.get("sentinel_timeout"), 90, 10, 300)
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
            "headless", "keep_browser_open", "one_profile_per_account", "delete_profile_after_run",
            "random_os", "random_profile_name", "humanize_delay", "humanize_browser_actions", "existing_account_login",
        ):
            roxy[key] = _as_bool(roxy.get(key), bool(DEFAULT_FREE_CONFIG["roxybrowser"][key]))
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
        result["version"] = 4
        return result

    def load(self) -> dict[str, Any]:
        with self._lock:
            try:
                value = json.loads(self.path.read_text(encoding="utf-8"))
            except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError):
                value = {}
            return self.normalize(value if isinstance(value, Mapping) else {})

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


def strip_legacy_free_config(value: Mapping[str, Any] | None) -> dict[str, Any]:
    result = dict(value or {})
    for key in FREE_LEGACY_CONFIG_KEYS:
        result.pop(key, None)
    return result


__all__ = [
    "DEFAULT_FREE_CONFIG", "FREE_LEGACY_CONFIG_KEYS", "FreeConfigStore", "strip_legacy_free_config",
]
