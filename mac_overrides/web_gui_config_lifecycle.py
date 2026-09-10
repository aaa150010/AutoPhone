"""Local-config read/write lifecycle for the recovered web GUI, hosted by web_gui.

Migration and persistence rules live here; runtime side effects (phone gate,
connectivity guard) stay in the host and are reached through the ``host``
argument so late-bound singletons keep their semantics.
"""

from __future__ import annotations

import copy
import json
from typing import Any

_LEGACY_UPLOAD_FIELDS = ("nvtoken", "nvtoken_upload", "pixel_upload_enabled")



try:
    from .quiet_note import note_stderr
except ImportError:  # pragma: no cover - top-level recovery import
    from quiet_note import note_stderr  # type: ignore[no-redef]

def _note_stderr(where: str, exc: BaseException) -> None:
    note_stderr('web_gui_config_lifecycle', where, exc)


def read_local_config(host):
    """Load the local config file, migrate it, and persist migrations."""
    config_file = host._LOCAL_CONFIG_FILE
    value: Any = {}
    if config_file.exists():
        try:
            value = json.loads(config_file.read_text(encoding="utf-8"))
        except Exception:
            return {}
    if not isinstance(value, dict):
        value = {}
    changed = False
    if any(field in value for field in _LEGACY_UPLOAD_FIELDS):
        for field in _LEGACY_UPLOAD_FIELDS:
            value.pop(field, None)
        changed = True
    value, timeout_migrated = host._migrate_email_timeout_config(value)
    value, email_proxy_scope_migrated = host._migrate_email_proxy_scope_config(value)
    value, performance_migrated = host._sms_runtime_ext.migrate_performance_config(value)
    if changed or timeout_migrated or email_proxy_scope_migrated or performance_migrated:
        host._write_local_config(value)
    return value


def write_local_config(host, data):
    """Migrate, persist, and push runtime-facing config into host singletons."""
    value = dict(data) if isinstance(data, dict) else {}
    previous = host._read_store_config(host._LOCAL_CONFIG_FILE)
    if "email_proxy_scope_strategy_version" not in value:
        prior_version = previous.get("email_proxy_scope_strategy_version")
        if prior_version is not None:
            value["email_proxy_scope_strategy_version"] = prior_version
    if "proxy_scope" not in value and isinstance(previous.get("proxy_scope"), dict):
        value["proxy_scope"] = copy.deepcopy(previous["proxy_scope"])
    value = host._free_register_config_ext.strip_legacy_free_config(value)
    for field in _LEGACY_UPLOAD_FIELDS:
        value.pop(field, None)
    value, _timeout_migrated = host._migrate_email_timeout_config(value)
    value, _email_proxy_scope_migrated = host._migrate_email_proxy_scope_config(value)
    value, _performance_migrated = host._sms_runtime_ext.migrate_performance_config(value)
    host._atomic_write_private_json(host._LOCAL_CONFIG_FILE, value)

    phone_gate = host.__dict__.get("_SMS_PHONE_GATE")
    if phone_gate is not None:
        try:
            phone_gate.configure(value.get("phone_submission_concurrency", 2))
        except Exception as exc:
            # Phone-gate configuration is best-effort at startup.
            _note_stderr("phone_gate_configure", exc)
    connectivity = host.__dict__.get("_OPENAI_CONNECTIVITY")
    if connectivity is not None:
        try:
            guard_enabled = host._performance_runtime_ext.as_bool(
                value.get("openai_connectivity_guard"),
                True,
            )
            was_paused = bool(connectivity.snapshot().get("paused"))
            connectivity.set_enabled(guard_enabled)
            if was_paused and not guard_enabled:
                host._PROTOCOL_GATE.resume_connectivity(host.__dict__.get("_CONNECTIVITY_PROXY", ""))
                resume = getattr(host.__dict__.get("_CURRENT_INFLIGHT_GATE"), "resume", None)
                if callable(resume):
                    resume()
                host._set_stall_notifications_suspended(False)
            connectivity.configure_proxy(value.get("proxy") or "")
        except Exception as exc:
            # Connectivity reconfiguration must not reject the saved settings.
            _note_stderr("connectivity_reconfigure", exc)
    return value


__all__ = ["read_local_config", "write_local_config"]
