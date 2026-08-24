"""Shared MFA completion for ordinary OAuth email verification flows."""

from __future__ import annotations

import base64
from collections.abc import Mapping
from dataclasses import dataclass
import threading
import re
from typing import Any, Callable
from urllib.parse import urljoin, urlsplit


_TOTP_SECRET_RE = re.compile(r"^[A-Z2-7]+=*$")
_MFA_PAGE_TYPES = frozenset({"mfa_otp", "mfa_challenge", "mfa_otp_verification"})
_MFA_PATH_PREFIXES = (
    "/mfa",
    "/mfa-challenge",
    "/mfa_challenge",
    "/two-factor",
    "/2fa",
    "/totp",
)


def normalize_page_type(value: Any) -> str:
    """Normalize provider page aliases before applying MFA routing."""
    text = str(value or "").strip().lower().replace("-", "_")
    return re.sub(r"[^a-z0-9_]+", "_", text)[:80].strip("_")


def _response_is_mfa(response: Any, page_type_get: Callable[[Any], Any]) -> bool:
    try:
        page_type = normalize_page_type(page_type_get(response))
    except Exception:
        page_type = ""
    if page_type in _MFA_PAGE_TYPES:
        return True
    if not isinstance(response, Mapping):
        return False
    candidates = [response.get("continue_url"), response.get("url")]
    page = response.get("page")
    if isinstance(page, Mapping):
        candidates.extend((page.get("continue_url"), page.get("url")))
    for candidate in candidates:
        try:
            path = urlsplit(
                urljoin("https://auth.openai.com/", str(candidate or ""))
            ).path.lower()
        except (TypeError, ValueError):
            continue
        if any(
            path == prefix or path.startswith(f"{prefix}/")
            for prefix in _MFA_PATH_PREFIXES
        ):
            return True
    return False


def normalize_totp_secret(secret: Any) -> str:
    """Return a validated, storage-safe Base32 TOTP seed."""
    value = str(secret or "").strip()
    if not value:
        return ""
    label = re.match(r"(?i)^(?:2fa|totp|secret|密钥)\s*[=:：]\s*(.+)$", value)
    if label:
        value = label.group(1).strip()
    normalized = re.sub(r"[\s-]+", "", value).upper()
    if not _TOTP_SECRET_RE.fullmatch(normalized):
        return ""
    unpadded = normalized.rstrip("=")
    if len(unpadded) < 8:
        return ""
    padded = unpadded + "=" * ((8 - len(unpadded) % 8) % 8)
    try:
        base64.b32decode(padded, casefold=True)
    except (ValueError, TypeError):
        return ""
    return unpadded


class TaskSecretRegistry:
    """Keep task-bound TOTP seeds available across provider worker threads."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._values: dict[str, str] = {}

    def remember(self, task_id: Any, secret: Any) -> None:
        task = str(task_id or "").strip()
        value = normalize_totp_secret(secret)
        if not task or not value:
            return
        with self._lock:
            self._values[task] = value

    def get(self, task_id: Any) -> str:
        task = str(task_id or "").strip()
        if not task:
            return ""
        with self._lock:
            return self._values.get(task, "")

    def clear(self, task_id: Any) -> None:
        task = str(task_id or "").strip()
        if not task:
            return
        with self._lock:
            self._values.pop(task, None)


def provider_task_id(
    provider: Any,
    *,
    fallback: Any = "",
    current_task_get: Callable[[], Any] | None = None,
) -> str:
    config = getattr(provider, "config", None)
    config_task_id = config.get("sms_task_id") if isinstance(config, dict) else ""
    try:
        current_task = current_task_get() if callable(current_task_get) else ""
    except Exception:
        current_task = ""
    return str(
        fallback
        or current_task
        or getattr(provider, "task_id", "")
        or config_task_id
        or ""
    ).strip()


def remember_provider_totp_secret(
    provider: Any,
    registry: TaskSecretRegistry,
    *,
    task_id: Any = "",
    current_task_get: Callable[[], Any] | None = None,
    allowed_client_id: str = "chatgpt_totp",
) -> bool:
    """Mark a provider as TOTP-backed and bind its validated seed to a task."""
    entry = getattr(provider, "entry", None)
    if str(getattr(entry, "oauth_client_id", "") or "").strip() != allowed_client_id:
        return False
    try:
        setattr(provider, "_gptphone_totp_expected", True)
    except Exception:
        pass
    secret = normalize_totp_secret(getattr(entry, "oauth_refresh_token", ""))
    task = provider_task_id(
        provider,
        fallback=task_id,
        current_task_get=current_task_get,
    )
    if secret and task:
        registry.remember(task, secret)
    return True


def runtime_task_id(
    config: Any,
    *,
    context_task_get: Callable[[], Any] | None = None,
    transport: Any = None,
    transport_task_id_get: Callable[[Any], Any] | None = None,
) -> str:
    """Resolve one task key before a transport config is replaced."""
    values: list[Any] = []
    if isinstance(config, Mapping):
        values.extend((config.get("sms_task_id"), config.get("run_id")))
    if callable(context_task_get):
        try:
            values.append(context_task_get())
        except Exception:
            pass
    if transport is not None and callable(transport_task_id_get):
        try:
            values.append(transport_task_id_get(transport))
        except Exception:
            pass
    for value in values:
        normalized = str(value or "").strip()
        if normalized:
            return normalized
    return ""


def bind_provider_totp_secret(
    provider: Any,
    registry: TaskSecretRegistry,
    *,
    task_id: Any = "",
    current_task_get: Callable[[], Any] | None = None,
) -> str:
    """Bind a TOTP provider and return the exact registry key used."""
    if provider is None:
        return ""
    bound_task = provider_task_id(
        provider,
        fallback=task_id,
        current_task_get=current_task_get,
    )
    if not remember_provider_totp_secret(
        provider,
        registry,
        task_id=bound_task,
        current_task_get=current_task_get,
    ):
        return ""
    return bound_task


def clear_task_secrets(registry: TaskSecretRegistry, *task_ids: Any) -> None:
    """Clear all non-empty task keys involved in one auth invocation."""
    for task_id in {str(value or "").strip() for value in task_ids}:
        if task_id:
            registry.clear(task_id)


def task_generation(
    task_id: Any,
    snapshot_get: Callable[[str], Any],
) -> int:
    """Read a bounded manual-verification generation from task state."""
    normalized = str(task_id or "").strip()
    if not normalized:
        return 0
    try:
        snapshot = snapshot_get(normalized)
        return max(0, int(snapshot.get("generation") or 0))
    except (AttributeError, TypeError, ValueError):
        return 0


def provider_stop_event(provider: Any) -> Any:
    """Resolve a provider stop event without coupling to recovered classes."""
    stop_event = getattr(provider, "stop_event", None)
    if stop_event is not None:
        return stop_event
    config = getattr(provider, "config", None)
    return config.get("_stop_requested") if isinstance(config, Mapping) else None


def transport_expects_totp(
    transport: Any,
    registry: TaskSecretRegistry,
    *,
    transport_task_id_get: Callable[[Any], Any],
    current_task_get: Callable[[], Any] | None = None,
    allowed_client_id: str = "chatgpt_totp",
) -> bool:
    if bool(getattr(transport, "_gptphone_totp_expected", False)):
        return True
    try:
        task_id = str(
            transport_task_id_get(transport)
            or (current_task_get() if callable(current_task_get) else "")
            or ""
        ).strip()
    except Exception:
        task_id = ""
    if task_id and registry.get(task_id):
        return True
    context = getattr(transport, "_gptphone_auth_challenge_context", None)
    provider = getattr(context, "email_otp_provider", None)
    if bool(getattr(provider, "_gptphone_totp_expected", False)):
        return True
    entry = getattr(provider, "entry", None)
    return str(getattr(entry, "oauth_client_id", "") or "").strip() == allowed_client_id


def clear_task_totp_secret(
    transport: Any,
    registry: TaskSecretRegistry,
    *,
    context_clear: Callable[..., Any],
    transport_task_id_get: Callable[[Any], Any],
    current_task_get: Callable[[], Any] | None = None,
) -> None:
    try:
        context_clear("")
    except TypeError:
        context_clear()
    try:
        task_id = str(
            transport_task_id_get(transport) if transport is not None else ""
        ).strip()
    except Exception:
        task_id = ""
    if not task_id and callable(current_task_get):
        try:
            task_id = str(current_task_get() or "").strip()
        except Exception:
            task_id = ""
    registry.clear(task_id)


def resolve_totp_secret(
    transport: Any,
    *,
    context_secret_get: Callable[[], Any],
    task_secret_get: Callable[[Any], Any],
    task_id_get: Callable[[Any], Any],
    allowed_client_id: str = "chatgpt_totp",
) -> str:
    """Resolve a TOTP seed without relying on ContextVar thread affinity."""
    try:
        value = normalize_totp_secret(context_secret_get())
    except Exception:
        value = ""
    if value:
        return value
    try:
        value = normalize_totp_secret(task_secret_get(task_id_get(transport)))
    except Exception:
        value = ""
    if value:
        return value
    value = normalize_totp_secret(getattr(transport, "_gptphone_totp_secret", ""))
    if value:
        return value
    context = getattr(transport, "_gptphone_auth_challenge_context", None)
    provider = getattr(context, "email_otp_provider", None)
    entry = getattr(provider, "entry", None)
    if str(getattr(entry, "oauth_client_id", "") or "").strip() != allowed_client_id:
        return ""
    return normalize_totp_secret(getattr(entry, "oauth_refresh_token", ""))


@dataclass(frozen=True)
class EmailOtpMfaRuntime:
    secret_get: Callable[..., str]
    secret_clear: Callable[[], None]
    checkpoint_save: Callable[[Any, Any], Any]
    response_error_code: Callable[[Any], str]
    page_type: Callable[[Any], str]
    observe_auth_step: Callable[[Any, Any, str], Any]
    continue_if_needed: Callable[..., Any]
    factor_id: Callable[[Any], str]
    verify_totp: Callable[..., Any]
    verify_mfa: Callable[..., Any]
    manual_fallback: Callable[[Any, Any], Any]
    session_invalid: Callable[[Any], bool]
    stop_event: Callable[[Any], Any]
    requires_secret: Callable[[Any], bool] | None = None

    def _secret(self, transport: Any) -> str:
        """Read the task-bound secret, including passwordless signup flows."""
        try:
            value = self.secret_get(transport)
        except TypeError:
            # Preserve compatibility with the original zero-argument hook.
            value = self.secret_get()
        return normalize_totp_secret(value)

    def _requires_secret(self, transport: Any) -> bool:
        callback = self.requires_secret
        if callable(callback):
            try:
                return bool(callback(transport))
            except Exception:
                return False
        return False

    @staticmethod
    def _secret_missing_response(response: Any, code: str) -> dict[str, Any]:
        result = dict(response) if isinstance(response, dict) else {}
        messages = {
            "mfa_totp_secret_missing": (
                "mfa_totp_secret_missing: 当前任务未绑定有效 2FA 密钥"
            ),
            "mfa_factor_id_missing": (
                "mfa_factor_id_missing: MFA 页面未返回有效验证因子"
            ),
        }
        result["error"] = {
            "code": code,
            # The recovered chain's _error_text reads only this message. Keep
            # the stable classifier code here as well as in the structured
            # field/private marker so the failure node survives that boundary.
            "message": messages.get(
                code,
                f"{code}: 当前任务未绑定有效 2FA 密钥或 MFA 验证因子",
            ),
        }
        result["_gptphone_mfa_failure"] = code
        return result

    def _clear_secret(self, transport: Any) -> None:
        try:
            self.secret_clear(transport)
        except TypeError:
            # Preserve compatibility with the original zero-argument hook.
            self.secret_clear()

    def verify(self, transport: Any, code: str, original_verify: Callable[..., Any]) -> Any:
        response = original_verify(transport, code)
        self.checkpoint_save(transport, response)
        secret = self._secret(transport)
        self._clear_secret(transport)
        if self.response_error_code(response) == "incorrect_code":
            self.observe_auth_step(transport, response, "email_code_verifying")
            return response

        mfa_page = _response_is_mfa(response, self.page_type)
        log_fn = getattr(transport, "log_fn", None)
        if mfa_page and not secret and callable(log_fn):
            try:
                log_fn("  [2FA/mfa_otp_verifying] 检测到 MFA 页面，但当前任务未绑定可用 2FA 密钥", "error")
            except TypeError:
                log_fn("  [2FA/mfa_otp_verifying] 检测到 MFA 页面，但当前任务未绑定可用 2FA 密钥")
        if mfa_page and not secret:
            # An MFA challenge after the URL mailbox OTP is an authenticator
            # step. Without a bound seed, stop before the recovered chain can
            # mistake its /mfa-challenge URL for an OAuth callback.
            self.observe_auth_step(transport, response, "mfa_otp_verifying")
            if getattr(transport, "_gptphone_free_protocol_state_machine", False):
                return response
            return self._secret_missing_response(response, "mfa_totp_secret_missing")
        if not mfa_page or not secret:
            self.observe_auth_step(transport, response, "email_code_verifying")
            if getattr(transport, "_gptphone_free_protocol_state_machine", False):
                return response
            return self.continue_if_needed(transport, response, origin="email_otp")

        factor_id = self.factor_id(response)
        if not factor_id:
            if callable(log_fn):
                try:
                    log_fn("  [2FA/mfa_otp_verifying] MFA 页面未返回有效验证因子", "error")
                except TypeError:
                    log_fn("  [2FA/mfa_otp_verifying] MFA 页面未返回有效验证因子")
            self.observe_auth_step(transport, response, "mfa_otp_verifying")
            if getattr(transport, "_gptphone_free_protocol_state_machine", False):
                return response
            return self._secret_missing_response(response, "mfa_factor_id_missing")

        if callable(log_fn):
            try:
                log_fn("  [Codex] 邮箱验证码后遇到 MFA，正在验证 2FA 动态码", "info")
            except TypeError:
                log_fn("  [Codex] 邮箱验证码后遇到 MFA，正在验证 2FA 动态码")

        response = self.verify_totp(
            transport,
            factor_id=factor_id,
            secret=secret,
            verify_fn=self.verify_mfa,
            manual_fallback_fn=self.manual_fallback,
            session_invalid_fn=self.session_invalid,
            stop_event=self.stop_event(transport),
            log_fn=log_fn,
        )
        self.checkpoint_save(transport, response)
        self.observe_auth_step(transport, response, "mfa_otp_verifying")
        if self.response_error_code(response) == "incorrect_code":
            return response
        if getattr(transport, "_gptphone_free_protocol_state_machine", False):
            return response
        return self.continue_if_needed(transport, response, origin="email_otp")


__all__ = [
    "EmailOtpMfaRuntime",
    "TaskSecretRegistry",
    "normalize_totp_secret",
    "normalize_page_type",
    "provider_task_id",
    "remember_provider_totp_secret",
    "runtime_task_id",
    "bind_provider_totp_secret",
    "clear_task_secrets",
    "task_generation",
    "provider_stop_event",
    "resolve_totp_secret",
    "transport_expects_totp",
    "clear_task_totp_secret",
]
