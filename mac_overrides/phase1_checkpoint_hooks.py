"""Runtime hooks for encrypted phase-one OAuth checkpoint recovery.

The recovered OAuth chain already understands a private ``phase1_active_session``
configuration value.  This module supplies the small adapter around that
contract: it derives a stable mailbox identity, captures the live browser
session, and keeps checkpoint status out of task persistence and public state.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
import copy
import re
import threading
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

try:
    from .phase1_checkpoint_runtime import CheckpointLeaseLost
except ImportError:  # Loaded as a top-level runtime override by web_gui.py.
    from phase1_checkpoint_runtime import CheckpointLeaseLost


_DROP_KEY = re.compile(
    r"(?:^|_)(?:code|otp|password|passcode|verification_code|totp_secret)$",
    re.IGNORECASE,
)
_DROP_QUERY_KEY = re.compile(r"(?:^|_)(?:code|otp|passcode|verification_code)$", re.IGNORECASE)
_DELETE_CHECKPOINT_STATUSES = frozenset({"success", "account_banned"})
_DELETE_CHECKPOINT_MARKERS = (
    "account_mismatch",
    "email_mismatch",
    "sub2_update_binding_mismatch",
    "oauth_account_mismatch",
    "checkpoint_expired",
    "checkpoint_invalid",
)


def _snake_key(value: Any) -> str:
    """Normalize provider field names for policy checks without rewriting them."""
    text = str(value or "").strip()
    if not text:
        return ""
    text = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", text)
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", text)
    text = re.sub(r"[^A-Za-z0-9]+", "_", text)
    return text.strip("_").lower()


class CheckpointPublicState:
    """Thread-safe task-scoped public checkpoint status without payloads."""

    def __init__(self) -> None:
        self._values: dict[str, dict[str, Any]] = {}
        self._lock = threading.RLock()

    def update(self, task_id: Any, value: Mapping[str, Any] | None) -> None:
        identifier = _text(task_id)
        if not identifier:
            return
        with self._lock:
            if isinstance(value, Mapping) and value:
                self._values[identifier] = copy.deepcopy(dict(value))
            else:
                self._values.pop(identifier, None)

    def get(self, task_id: Any) -> dict[str, Any] | None:
        with self._lock:
            value = self._values.get(_text(task_id))
            return copy.deepcopy(value) if isinstance(value, dict) else None


def _text(value: Any) -> str:
    return str(value or "").strip()


def should_delete_checkpoint(
    status: Any,
    *,
    invalid_session: bool = False,
    values: Any = (),
) -> bool:
    """Keep resumable failures, while deleting sessions that cannot be reused."""
    if invalid_session:
        return True
    if _text(status).lower() in _DELETE_CHECKPOINT_STATUSES:
        return True
    rows = values if isinstance(values, (list, tuple, set, frozenset)) else (values,)
    text = " ".join(_text(value).lower() for value in rows)
    return any(marker in text for marker in _DELETE_CHECKPOINT_MARKERS)


def checkpoint_context_for_entry(
    importer: Any,
    settings: Any,
    entry: Any,
    task_id: Any,
    *,
    row_id_from_source: Callable[[Any], Any],
) -> dict[str, str]:
    source = _text(getattr(entry, "source_row", ""))
    if not source and entry is not None:
        try:
            source = _text(importer._source_row(entry))
        except Exception:
            source = ""
    try:
        row_id = row_id_from_source(source) if source else ""
    except Exception:
        row_id = ""
    return {
        "task_id": _text(task_id),
        "row_id": _text(row_id).lower(),
        "email": _text(getattr(entry, "email", "")).lower(),
        "proxy": _text((settings or {}).get("proxy")),
        "batch_id": _text((settings or {}).get("batch_id"))[:80],
    }


def _safe_query_url(value: Any) -> str:
    raw = _text(value)
    if not raw:
        return ""
    try:
        parsed = urlsplit(raw)
        query = urlencode(
            [(key, val) for key, val in parse_qsl(parsed.query, keep_blank_values=True)
             if not _DROP_QUERY_KEY.search(_snake_key(key))],
            doseq=True,
        )
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, parsed.fragment))
    except (TypeError, ValueError):
        return raw[:2048]


def _clean_response(value: Any, *, depth: int = 0) -> Any:
    """Remove one-time verification values before encrypting a response."""
    if depth > 8:
        return None
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for raw_key, raw_value in value.items():
            key = str(raw_key)
            normalized_key = _snake_key(key)
            if _DROP_KEY.search(normalized_key):
                continue
            if normalized_key.endswith("_url") or normalized_key == "url":
                result[key] = _safe_query_url(raw_value)
            else:
                result[key] = _clean_response(raw_value, depth=depth + 1)
        return result
    if isinstance(value, (list, tuple)):
        return [_clean_response(item, depth=depth + 1) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return _text(value)[:512]


def cookie_snapshot(transport: Any) -> list[dict[str, Any]]:
    session = getattr(transport, "session", None)
    jar = getattr(session, "cookies", None)
    rows: list[dict[str, Any]] = []
    try:
        iterator = list(jar or ())
    except Exception:
        iterator = []
    for cookie in iterator:
        try:
            name = _text(getattr(cookie, "name", ""))
            value = str(getattr(cookie, "value", "") or "")
            if not name or not value:
                continue
            rows.append(
                {
                    "name": name,
                    "value": value,
                    "domain": _text(getattr(cookie, "domain", "")),
                    "path": _text(getattr(cookie, "path", "")) or "/",
                    "secure": bool(getattr(cookie, "secure", False)),
                }
            )
        except Exception:
            continue
    return rows


def live_snapshot(transport: Any, response: Any = None, *, continue_url: Any = "") -> dict[str, Any]:
    """Build the private payload accepted by ``RealCodexTransport``."""
    cookies = cookie_snapshot(transport)
    sentinel = getattr(getattr(transport, "sentinel_provider", None), "_cache", {})
    try:
        sentinel_cache = copy.deepcopy(dict(sentinel or {})) if isinstance(sentinel, Mapping) else {}
    except Exception:
        sentinel_cache = {}
    response_url = ""
    if isinstance(response, Mapping):
        response_url = next(
            (_text(response.get(key)) for key in ("continue_url", "external_url", "_location", "url")
             if _text(response.get(key))),
            "",
        )
    latest_url = _safe_query_url(
        continue_url
        or response_url
        or getattr(transport, "_gptphone_auth_continue_url", "")
        or getattr(transport, "_chatgpt_totp_mfa_continue_url", "")
    )
    value = {
        "ready": bool(cookies),
        "cookies": cookies,
        "device_id": _text(getattr(transport, "device_id", "")),
        "sentinel_cache": sentinel_cache,
        "response": _clean_response(response if isinstance(response, Mapping) else {}),
        "continue_url": latest_url,
    }
    return value


def import_phase1_session(
    transport: Any,
    snapshot: Any,
    *,
    original: Callable[[Any, Any], Any],
    coordinator: Any,
) -> Any:
    try:
        imported = original(transport, snapshot)
    except Exception:
        if not getattr(transport, "_gptphone_checkpoint_restored", False):
            raise
        coordinator.discard_import_failure(transport)
        setattr(transport, "_gptphone_checkpoint_restored", False)
        return False
    if getattr(transport, "_gptphone_checkpoint_restored", False) and not imported:
        coordinator.discard_import_failure(transport)
        setattr(transport, "_gptphone_checkpoint_restored", False)
    elif imported:
        setattr(transport, "_gptphone_checkpoint_imported", True)
    return imported


def save_after_auth(
    transport: Any,
    response: Any,
    *,
    run_mode: Callable[[], Any],
    session_invalid: Callable[[Any], bool],
    success: Callable[[Any], bool],
    coordinator: Any,
) -> Any:
    if str(run_mode() or "").strip().lower() == "relogin":
        return None
    if session_invalid(response):
        return None
    try:
        if not success(response):
            return None
    except Exception:
        return None
    return coordinator.save(transport, response)


def delete_after_auth(
    transport: Any,
    *,
    run_mode: Callable[[], Any],
    coordinator: Any,
) -> Any:
    if str(run_mode() or "").strip().lower() != "relogin":
        return coordinator.delete(transport)
    return None


class CheckpointAuthHooks:
    """Bind recovered transport methods to checkpoint policy callbacks."""

    def __init__(
        self,
        *,
        original_import: Callable[[Any, Any], Any],
        run_mode: Callable[[], Any],
        session_invalid: Callable[[Any], bool],
        success: Callable[[Any], bool],
        coordinator: Any,
    ) -> None:
        self.original_import = original_import
        self.run_mode = run_mode
        self.session_invalid = session_invalid
        self.success = success
        self.coordinator = coordinator

    def import_phase1_session(self, transport: Any, snapshot: Any) -> Any:
        return import_phase1_session(
            transport,
            snapshot,
            original=self.original_import,
            coordinator=self.coordinator,
        )

    def save_after_auth(self, transport: Any, response: Any) -> Any:
        return save_after_auth(
            transport,
            response,
            run_mode=self.run_mode,
            session_invalid=self.session_invalid,
            success=self.success,
            coordinator=self.coordinator,
        )

    def delete_after_auth(self, transport: Any) -> Any:
        return delete_after_auth(
            transport,
            run_mode=self.run_mode,
            coordinator=self.coordinator,
        )


class CheckpointCoordinator:
    """Coordinate one task's checkpoint without exposing its encrypted payload."""

    def __init__(
        self,
        store: Any,
        *,
        context_getter: Callable[[], Mapping[str, Any] | None],
        generation_getter: Callable[[str], Any] | None = None,
        public_update: Callable[[str, Mapping[str, Any] | None], Any] | None = None,
        log_fn: Callable[[str, str], Any] | None = None,
    ) -> None:
        self.store = store
        self.context_getter = context_getter
        self.generation_getter = generation_getter
        self.public_update = public_update
        self.log_fn = log_fn

    def _context(self, transport: Any) -> dict[str, str]:
        raw = self.context_getter() if callable(self.context_getter) else None
        value = dict(raw or {}) if isinstance(raw, Mapping) else {}
        config = getattr(transport, "config", None)
        if isinstance(config, Mapping):
            for key in ("row_id", "email", "proxy", "batch_id", "task_id"):
                value.setdefault(key, config.get(f"_checkpoint_{key}") or config.get(key) or "")
        value.setdefault("task_id", config.get("sms_task_id") if isinstance(config, Mapping) else "")
        value["task_id"] = _text(value.get("task_id"))
        value["row_id"] = _text(value.get("row_id"))
        value["email"] = _text(value.get("email") or getattr(transport, "account_email", "")).lower()
        value["proxy"] = _text(value.get("proxy") or getattr(transport, "proxy", ""))
        value["batch_id"] = _text(value.get("batch_id"))
        return value

    def _generation(self, task_id: str) -> int:
        if not callable(self.generation_getter):
            return 0
        try:
            return max(0, int(self.generation_getter(task_id) or 0))
        except (TypeError, ValueError, AttributeError):
            return 0

    @staticmethod
    def _stop_event(transport: Any) -> Any:
        """Return the importer stop signal without persisting it in a snapshot."""
        value = getattr(transport, "stop_event", None)
        if value is not None:
            return value
        config = getattr(transport, "config", None)
        return config.get("_stop_requested") if isinstance(config, Mapping) else None

    def _public(self, task_id: str, value: Mapping[str, Any] | None) -> None:
        if callable(self.public_update) and task_id:
            try:
                self.public_update(task_id, value)
            except Exception:
                pass

    def restore(self, transport: Any) -> dict[str, Any] | None:
        # A transport/config object can be reused across an OAuth retry.  Do
        # not let a previously injected private snapshot survive a failed,
        # expired, or identity-mismatched load and re-enter the recovered
        # chain as if it were a fresh checkpoint.
        config = getattr(transport, "config", None)
        if isinstance(config, dict):
            config.pop("phase1_active_session", None)
        identity = self._context(transport)
        if not identity["row_id"] or not identity["email"]:
            return None
        try:
            was_enabled = bool(getattr(self.store, "enabled", True))
            loaded = self.store.load(
                row_id=identity["row_id"],
                email=identity["email"],
                proxy=identity["proxy"],
                task_generation=self._generation(identity["task_id"]),
                claim_id=identity["task_id"],
                stop_event=self._stop_event(transport),
            )
        except Exception as exc:
            self._log("  [OAuth checkpoint/oauth_session] checkpoint 校验失败，已回退 fresh OAuth", "warn")
            self._public(identity["task_id"], None)
            return None
        if not isinstance(loaded, Mapping):
            if was_enabled and not bool(getattr(self.store, "enabled", True)):
                self._log(
                    "  [OAuth checkpoint/oauth_session] Keychain 不可用，checkpoint 已禁用，继续 fresh OAuth",
                    "warn",
                )
                status_fn = getattr(self.store, "public_status", None)
                if callable(status_fn):
                    try:
                        self._public(identity["task_id"], status_fn(state="disabled"))
                    except Exception:
                        self._public(identity["task_id"], {"state": "disabled"})
            return None
        snapshot = loaded.get("snapshot")
        if not isinstance(snapshot, Mapping) or not snapshot.get("ready"):
            try:
                self.store.delete(identity["row_id"])
            except Exception:
                pass
            return None
        if isinstance(config, dict):
            # This is deliberately private and is consumed by the recovered
            # chain only; it never enters persisted task or API state.
            config["phase1_active_session"] = copy.deepcopy(dict(snapshot))
        setattr(transport, "_gptphone_checkpoint_restored", True)
        self._public(identity["task_id"], loaded.get("public"))
        self._log("  [OAuth checkpoint/oauth_session] 已恢复邮箱阶段会话，将从手机号阶段继续", "info")
        return dict(loaded)

    def save(self, transport: Any, response: Any = None, *, resume_stage: str = "phone_acquiring") -> dict[str, Any] | None:
        identity = self._context(transport)
        if not identity["row_id"] or not identity["email"]:
            return None
        snapshot = live_snapshot(transport, response)
        if not snapshot.get("ready"):
            return None
        try:
            status = self.store.save(
                row_id=identity["row_id"],
                email=identity["email"],
                proxy=identity["proxy"],
                snapshot=snapshot,
                batch_id=identity["batch_id"],
                task_generation=self._generation(identity["task_id"]),
                resume_stage=resume_stage,
                stop_event=self._stop_event(transport),
            )
        except CheckpointLeaseLost:
            # A restarted task may have atomically reclaimed this mailbox
            # between auth steps.  Preserve the newer owner's ciphertext.
            self._log(
                "  [OAuth checkpoint/oauth_session] checkpoint 已被其他任务认领，保留新任务会话",
                "warn",
            )
            return None
        except Exception as exc:
            # Keychain failure disables the store internally; the original
            # OAuth flow continues without a plaintext fallback.
            self._log("  [OAuth checkpoint/oauth_session] Keychain 不可用，已关闭 checkpoint，继续当前流程", "warn")
            return None
        self._public(identity["task_id"], status)
        return status

    def delete(self, transport: Any = None, *, identity: Mapping[str, Any] | None = None) -> None:
        value = dict(identity or self._context(transport))
        row_id = _text(value.get("row_id"))
        if not row_id:
            return
        try:
            self.store.delete(row_id)
        except Exception:
            pass
        self._public(_text(value.get("task_id")), None)

    def release(self, transport: Any = None, *, identity: Mapping[str, Any] | None = None) -> bool:
        """Make a retained checkpoint claimable by the mailbox's next task."""
        value = dict(identity or self._context(transport))
        row_id = _text(value.get("row_id"))
        if not row_id:
            return False
        try:
            return bool(
                self.store.release(
                    row_id,
                    claim_id=_text(value.get("task_id")),
                )
            )
        except Exception:
            return False

    def discard_import_failure(self, transport: Any) -> None:
        """Discard an unusable restored snapshot before the chain retries fresh OAuth."""
        self.delete(transport)
        config = getattr(transport, "config", None)
        if isinstance(config, dict):
            config.pop("phase1_active_session", None)
        self._log(
            "  [OAuth checkpoint/oauth_session] 活会话导入失败，已清除 checkpoint 并回退 fresh OAuth",
            "warn",
        )

    def cleanup_terminal(self, *, identity: Mapping[str, Any]) -> None:
        """A terminal task must never leave a reusable phase-one session behind."""
        self.delete(identity=identity)

    def _log(self, message: str, level: str) -> None:
        if not callable(self.log_fn):
            return
        try:
            self.log_fn(message, level)
        except TypeError:
            self.log_fn(message)


__all__ = [
    "CheckpointAuthHooks",
    "CheckpointCoordinator",
    "CheckpointPublicState",
    "checkpoint_context_for_entry",
    "cookie_snapshot",
    "delete_after_auth",
    "import_phase1_session",
    "live_snapshot",
    "save_after_auth",
    "should_delete_checkpoint",
]
