"""Encrypted phase-one OAuth checkpoints for interruption recovery."""

from __future__ import annotations

import base64
from collections.abc import Mapping
from contextlib import contextmanager
import hashlib
import inspect
import json
import os
from pathlib import Path
import secrets
import subprocess  # Compatibility for callers that monkeypatch this module.
import tempfile
import threading
import time
from typing import Any, Callable

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

try:
    import fcntl
except ImportError:  # pragma: no cover - macOS and Linux provide fcntl.
    fcntl = None

try:
    from .keychain_runtime import (
        CheckpointDisabled,
        CheckpointError,
        DEFAULT_KEYCHAIN_TIMEOUT_SECONDS,
        KEY_SERVICE,
        KeychainOperationStopped,
        KeychainUnavailable,
        SecurityKeyProvider,
    )
except ImportError:  # Loaded as a top-level runtime override by web_gui.py.
    from keychain_runtime import (
        CheckpointDisabled,
        CheckpointError,
        DEFAULT_KEYCHAIN_TIMEOUT_SECONDS,
        KEY_SERVICE,
        KeychainOperationStopped,
        KeychainUnavailable,
        SecurityKeyProvider,
    )


SCHEMA_VERSION = 1
DEFAULT_TTL_SECONDS = 30 * 60


class CheckpointLeaseLost(CheckpointError):
    """Raised when an older task tries to overwrite a reclaimed checkpoint."""


def _text(value: Any) -> str:
    return str(value or "").strip()


def fingerprint(value: Any, *, length: int = 16) -> str:
    text = _text(value).lower()
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:length] if text else ""


def _email_hash(value: Any) -> str:
    return hashlib.sha256(_text(value).lower().encode("utf-8", "replace")).hexdigest()


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii")


def _unb64(value: Any) -> bytes:
    return base64.urlsafe_b64decode(str(value or "").encode("ascii"))


class Phase1CheckpointStore:
    """One encrypted checkpoint per stable mailbox row."""

    def __init__(
        self,
        root: str | os.PathLike[str],
        *,
        key_provider: Any | None = None,
        clock: Callable[[], float] = time.time,
        enabled: bool = True,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
    ) -> None:
        self.root = Path(root)
        self.key_provider = key_provider or SecurityKeyProvider()
        self.clock = clock
        self.enabled = bool(enabled)
        self.ttl_seconds = max(60, min(24 * 3600, int(ttl_seconds)))
        self._lock = threading.RLock()
        self._key: bytes | None = None
        self._key_attempted = False
        self._disabled_reason = ""
        # A process-scoped owner permits recovery after a process interruption
        # while preventing a second task in this process from stealing a live
        # session.
        self._process_owner = secrets.token_hex(16)
        # Keep a local lease record in addition to the authenticated metadata.
        # A restarted process has no record and may reclaim an interrupted
        # checkpoint, while an older process that lost that lease must not be
        # able to steal it back on its next retry.
        self._claimed_rows: dict[str, str] = {}
        if self.enabled:
            self.root.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(self.root, 0o700)
            except OSError:
                pass

    def _load_key(
        self,
        *,
        stop_event: Any = None,
        timeout_seconds: float | None = None,
    ) -> bytes:
        getter = getattr(self.key_provider, "get_or_create")
        kwargs: dict[str, Any] = {}
        if stop_event is not None:
            kwargs["stop_event"] = stop_event
        if timeout_seconds is not None:
            kwargs["timeout_seconds"] = timeout_seconds
        if kwargs:
            # Keep older injected key providers (whose method has no keyword
            # arguments) working without masking TypeErrors raised by their
            # actual implementation.
            try:
                signature = inspect.signature(getter)
            except (TypeError, ValueError):
                signature = None
            if signature is not None:
                accepts_kwargs = any(
                    parameter.kind is inspect.Parameter.VAR_KEYWORD
                    for parameter in signature.parameters.values()
                )
                accepted = {
                    name
                    for name, parameter in signature.parameters.items()
                    if parameter.kind
                    in (inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.KEYWORD_ONLY)
                }
                if not accepts_kwargs:
                    kwargs = {name: value for name, value in kwargs.items() if name in accepted}
            value = getter(**kwargs) if kwargs else getter()
        else:
            value = getter()
        if not isinstance(value, bytes) or len(value) != 32:
            raise KeychainUnavailable("checkpoint 加密密钥长度无效")
        return value

    def _ensure_key(self, *, stop_event: Any = None, timeout_seconds: float | None = None) -> bool:
        # Serialize the process-wide first-use attempt.  Without this lock,
        # parallel tasks can all observe an uninitialized key and race the
        # Keychain helper; the losing tasks then permanently skip checkpoint
        # work even when the first attempt succeeds.
        with self._lock:
            if not self.enabled:
                return False
            if self._key is not None:
                return True
            if self._key_attempted:
                return False
            self._key_attempted = True
            try:
                self._key = self._load_key(
                    stop_event=stop_event,
                    timeout_seconds=timeout_seconds,
                )
            except KeychainOperationStopped as exc:
                # A manual stop is scoped to the current batch. Keep the
                # provider usable for the next batch instead of permanently
                # disabling checkpoint support because this attempt was
                # cancelled before the key was created.
                self._key_attempted = False
                self._disabled_reason = str(exc)
                return False
            except CheckpointDisabled as exc:
                self.enabled = False
                self._disabled_reason = str(exc)
                return False
            except Exception:
                # A provider implementation can fail before it has a chance
                # to translate the platform error. Never keep retrying or
                # fall back to plaintext in that case.
                self.enabled = False
                self._disabled_reason = "macOS Keychain 不可用，已禁用 OAuth checkpoint"
                return False
            return True

    def _path(self, row_id: Any) -> Path:
        name = fingerprint(row_id, length=64)
        if not name:
            raise CheckpointError("邮箱 row id 为空")
        return self.root / f"{name}.json"

    def _aad(self, meta: Mapping[str, Any]) -> bytes:
        return json.dumps(dict(meta), ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def save(
        self,
        *,
        row_id: Any,
        email: Any,
        proxy: Any,
        snapshot: Mapping[str, Any],
        batch_id: Any = "",
        task_generation: Any = 0,
        resume_stage: str = "phone_acquiring",
        ttl_seconds: int | None = None,
        stop_event: Any = None,
        keychain_timeout_seconds: float | None = None,
    ) -> dict[str, Any]:
        if not self._ensure_key(
            stop_event=stop_event,
            timeout_seconds=keychain_timeout_seconds,
        ) or self._key is None:
            raise CheckpointDisabled(self._disabled_reason or "checkpoint 已禁用")
        if not isinstance(snapshot, Mapping) or not snapshot.get("ready"):
            raise CheckpointError("phase1 snapshot 未就绪")
        now = int(self.clock())
        ttl = self.ttl_seconds if ttl_seconds is None else max(60, min(24 * 3600, int(ttl_seconds)))
        meta = {
            "schema": SCHEMA_VERSION,
            "row_id": _text(row_id),
            "email_hash": _email_hash(email),
            "proxy_fingerprint": fingerprint(proxy),
            "batch_id": _text(batch_id)[:80],
            "task_generation": max(0, int(task_generation or 0)),
            "resume_stage": _text(resume_stage)[:80] or "phone_acquiring",
            "created_at": now,
            "expires_at": now + ttl,
        }
        payload = json.dumps(dict(snapshot), ensure_ascii=True, separators=(",", ":"), default=str).encode("utf-8")
        nonce = secrets.token_bytes(12)
        encrypted = AESGCM(self._key).encrypt(nonce, payload, self._aad(meta))
        envelope = {"meta": meta, "nonce": _b64(nonce), "ciphertext": _b64(encrypted)}
        path = self._path(row_id)
        row_key = _text(row_id)
        with self._lock, self._process_lock():
            # A process that was interrupted may leave a claimed checkpoint
            # behind.  Once another process reclaims it, the old process must
            # not be able to write a newer response over that task's session.
            # Fail closed even when the file disappeared or became malformed.
            local_claimant = self._claimed_rows.get(row_key)
            existing_meta = self._read_meta(path)
            if local_claimant:
                if (
                    not existing_meta
                    or _text(existing_meta.get("claim_owner")) != self._process_owner
                    or _text(existing_meta.get("claimed_by")) != local_claimant
                ):
                    raise CheckpointLeaseLost("checkpoint lease 已被其他任务认领")
            elif existing_meta and _text(existing_meta.get("claimed_by")):
                raise CheckpointLeaseLost("checkpoint lease 已被其他任务认领")

            if local_claimant and existing_meta:
                # Preserve the authenticated lease while the same task updates
                # its response/continue URL after the 2FA step.
                for key in ("claimed_generation", "claimed_at", "claimed_by", "claim_owner"):
                    if key in existing_meta:
                        meta[key] = existing_meta[key]
                # The lease fields are part of AES-GCM AAD, so re-encrypt the
                # envelope after carrying them forward.
                self._rewrite_envelope(path, meta, snapshot)
            else:
                self._atomic_write(path, envelope)
            if not local_claimant:
                self._claimed_rows.pop(row_key, None)
        return self.public_status(meta, state="saved")

    def load(
        self,
        *,
        row_id: Any,
        email: Any,
        proxy: Any,
        task_generation: Any = 0,
        claim: bool = True,
        claim_id: Any = "",
        stop_event: Any = None,
        keychain_timeout_seconds: float | None = None,
    ) -> dict[str, Any] | None:
        if not self._ensure_key(
            stop_event=stop_event,
            timeout_seconds=keychain_timeout_seconds,
        ) or self._key is None:
            return None
        path = self._path(row_id)
        with self._lock, self._process_lock():
            try:
                envelope = json.loads(path.read_text(encoding="utf-8"))
            except (FileNotFoundError, OSError, ValueError):
                return None
            meta = envelope.get("meta") if isinstance(envelope, Mapping) else None
            if not isinstance(meta, Mapping) or not self._matches(meta, row_id, email, proxy):
                self._safe_unlink(path)
                return None
            now = int(self.clock())
            try:
                expires = int(meta.get("expires_at") or 0)
                nonce = _unb64(envelope.get("nonce"))
                ciphertext = _unb64(envelope.get("ciphertext"))
                payload = AESGCM(self._key).decrypt(nonce, ciphertext, self._aad(meta))
                snapshot = json.loads(payload.decode("utf-8"))
            except (ValueError, TypeError, KeyError, OSError, InvalidTag):
                self._safe_unlink(path)
                return None
            if expires <= now or not isinstance(snapshot, Mapping) or not snapshot.get("ready"):
                self._safe_unlink(path)
                return None
            claimant = _text(claim_id) or f"generation:{max(0, int(task_generation or 0))}"
            claimed_by = _text(meta.get("claimed_by"))
            local_claimant = self._claimed_rows.get(_text(row_id))
            if claim and local_claimant:
                # This instance previously held the row. If another process
                # replaced the lease, it is permanently stale for this
                # instance, including retries using the old task id.
                if _text(meta.get("claim_owner")) != self._process_owner:
                    return None
                if claimed_by != claimant:
                    return None
            if claim and claimed_by and claimed_by != claimant:
                claim_owner = _text(meta.get("claim_owner"))
                # A different task in this process may still be using the
                # session. A different process indicates an interrupted run
                # and may atomically take ownership under the file lock.
                if not claim_owner or claim_owner == self._process_owner:
                    return None
            result = {
                "snapshot": dict(snapshot),
                "meta": dict(meta),
                "public": self.public_status(meta, state="restored", now=now),
            }
            if claim:
                # Keep a task-scoped mailbox lease in authenticated metadata.
                # The first claimant wins; retries by that task remain
                # idempotent until terminal cleanup removes the checkpoint.
                updated = dict(meta)
                updated["claimed_generation"] = max(0, int(task_generation or 0))
                updated["claimed_at"] = now
                updated["claimed_by"] = claimant
                updated["claim_owner"] = self._process_owner
                self._rewrite_envelope(path, updated, snapshot)
                self._claimed_rows[_text(row_id)] = claimant
            return result

    def delete(self, row_id: Any) -> None:
        try:
            path = self._path(row_id)
        except CheckpointError:
            return
        with self._lock, self._process_lock():
            self._safe_unlink(path)
            self._claimed_rows.pop(_text(row_id), None)

    def release(
        self,
        row_id: Any,
        *,
        claim_id: Any = "",
        stop_event: Any = None,
        keychain_timeout_seconds: float | None = None,
    ) -> bool:
        """Release this process's completed task lease without deleting payload."""
        if not self._ensure_key(
            stop_event=stop_event,
            timeout_seconds=keychain_timeout_seconds,
        ) or self._key is None:
            return False
        try:
            path = self._path(row_id)
        except CheckpointError:
            return False
        row_key = _text(row_id)
        expected_claimant = _text(claim_id) or self._claimed_rows.get(row_key, "")
        with self._lock, self._process_lock():
            try:
                envelope = json.loads(path.read_text(encoding="utf-8"))
                meta = envelope.get("meta") if isinstance(envelope, Mapping) else None
                if not isinstance(meta, Mapping):
                    return False
                claimed_by = _text(meta.get("claimed_by"))
                if (
                    not claimed_by
                    or _text(meta.get("claim_owner")) != self._process_owner
                    or (expected_claimant and claimed_by != expected_claimant)
                ):
                    if self._claimed_rows.get(row_key) == expected_claimant:
                        self._claimed_rows.pop(row_key, None)
                    return False
                nonce = _unb64(envelope.get("nonce"))
                ciphertext = _unb64(envelope.get("ciphertext"))
                payload = AESGCM(self._key).decrypt(nonce, ciphertext, self._aad(meta))
                snapshot = json.loads(payload.decode("utf-8"))
            except (FileNotFoundError, OSError, ValueError, TypeError, KeyError, InvalidTag):
                return False
            if not isinstance(snapshot, Mapping) or not snapshot.get("ready"):
                return False
            released = dict(meta)
            for key in ("claimed_generation", "claimed_at", "claimed_by", "claim_owner"):
                released.pop(key, None)
            self._rewrite_envelope(path, released, snapshot)
            self._claimed_rows.pop(row_key, None)
            return True

    def prune(self) -> int:
        if not self.enabled or not self.root.exists():
            return 0
        removed = 0
        now = int(self.clock())
        with self._lock, self._process_lock():
            for path in self.root.glob("*.json"):
                try:
                    value = json.loads(path.read_text(encoding="utf-8"))
                    meta = value.get("meta") if isinstance(value, Mapping) else {}
                    expires = int((meta or {}).get("expires_at") or 0)
                except (AttributeError, OSError, ValueError, TypeError):
                    expires = 0
                if expires <= now:
                    self._safe_unlink(path)
                    for claimed_row in tuple(self._claimed_rows):
                        if fingerprint(claimed_row, length=64) == path.stem:
                            self._claimed_rows.pop(claimed_row, None)
                    removed += 1
        return removed

    def public_status(
        self,
        meta: Mapping[str, Any] | None = None,
        *,
        state: str = "none",
        now: int | None = None,
    ) -> dict[str, Any]:
        value = dict(meta or {})
        current = int(self.clock()) if now is None else int(now)
        created = int(value.get("created_at") or 0)
        expires = int(value.get("expires_at") or 0)
        return {
            "state": state if self.enabled else "disabled",
            "resume_stage": _text(value.get("resume_stage")),
            "expires_at": expires or None,
            "age_seconds": max(0, current - created) if created else 0,
            "remaining_seconds": max(0, expires - current) if expires else 0,
            "reason": self._disabled_reason if not self.enabled else "",
        }

    def _matches(self, meta: Mapping[str, Any], row_id: Any, email: Any, proxy: Any) -> bool:
        try:
            schema = int(meta.get("schema") or 0)
        except (TypeError, ValueError):
            return False
        return (
            schema == SCHEMA_VERSION
            and _text(meta.get("row_id")) == _text(row_id)
            and _text(meta.get("email_hash")) == _email_hash(email)
            and _text(meta.get("proxy_fingerprint")) == fingerprint(proxy)
        )

    @staticmethod
    def _read_meta(path: Path) -> dict[str, Any] | None:
        """Read only the envelope metadata for lease checks.

        The ciphertext is authenticated again by ``load``.  This lightweight
        read is deliberately fail-closed for an existing claimed file; it is
        only used to prevent stale writers from replacing a live lease.
        """
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (FileNotFoundError, OSError, ValueError, TypeError):
            return None
        meta = value.get("meta") if isinstance(value, Mapping) else None
        return dict(meta) if isinstance(meta, Mapping) else None

    @contextmanager
    def _process_lock(self):
        """Serialize claim/read/rewrite across processes when supported."""
        if fcntl is None:
            yield
            return
        self.root.mkdir(parents=True, exist_ok=True)
        lock_path = self.root / ".checkpoint.lock"
        try:
            handle = lock_path.open("a+", encoding="utf-8")
            try:
                os.chmod(lock_path, 0o600)
            except OSError:
                pass
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        except OSError:
            # The per-instance lock still protects normal operation if the
            # optional filesystem lock cannot be established.
            yield
            return
        try:
            yield
        finally:
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            except OSError:
                pass
            handle.close()

    def _rewrite_envelope(self, path: Path, meta: Mapping[str, Any], snapshot: Mapping[str, Any]) -> None:
        if self._key is None:
            return
        payload = json.dumps(dict(snapshot), ensure_ascii=True, separators=(",", ":"), default=str).encode("utf-8")
        nonce = secrets.token_bytes(12)
        envelope = {
            "meta": dict(meta),
            "nonce": _b64(nonce),
            "ciphertext": _b64(AESGCM(self._key).encrypt(nonce, payload, self._aad(meta))),
        }
        self._atomic_write(path, envelope)

    @staticmethod
    def _atomic_write(path: Path, value: Mapping[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(dict(value), handle, ensure_ascii=True, separators=(",", ":"))
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
        finally:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass

    @staticmethod
    def _safe_unlink(path: Path) -> None:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            pass


__all__ = [
    "CheckpointDisabled",
    "CheckpointError",
    "CheckpointLeaseLost",
    "DEFAULT_TTL_SECONDS",
    "DEFAULT_KEYCHAIN_TIMEOUT_SECONDS",
    "KeychainOperationStopped",
    "KeychainUnavailable",
    "Phase1CheckpointStore",
    "SCHEMA_VERSION",
    "SecurityKeyProvider",
    "fingerprint",
]
