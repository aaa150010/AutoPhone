"""Small, dependency-free contracts for the Free Camoufox flow.

The browser implementation is intentionally kept out of this module.  These
types are the boundary shared by the state machine, transport adapter and
manager, so they can be imported in environments where Camoufox is not
installed (for example, API workers and unit tests).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
import copy
import math
import re
import time
from typing import Any, Mapping
from urllib.parse import urlsplit


class CamoufoxFlowState(StrEnum):
    """Stable public names for the states observed by the page classifier."""

    ENTRY = "entry"
    EMAIL_VERIFICATION = "email_verification"
    OTP = "otp"
    SIGNUP_PASSWORD = "signup_password"
    LOGIN_PASSWORD = "login_password"
    PROFILE = "profile"
    CONSENT = "consent"
    OAUTH_CALLBACK = "oauth_callback"
    HOME = "home"
    SECURITY = "security"
    EXTERNAL_AUTH = "external_auth"
    UNKNOWN = "unknown"


TERMINAL_FLOW_STATES = frozenset({
    CamoufoxFlowState.HOME,
    CamoufoxFlowState.SECURITY,
    CamoufoxFlowState.EXTERNAL_AUTH,
})


def normalize_flow_state(value: Any) -> CamoufoxFlowState:
    """Normalize a page classifier result without raising on unknown input."""

    if isinstance(value, CamoufoxFlowState):
        return value
    candidate = str(value or "").strip().casefold()
    aliases = {
        "email-verification": CamoufoxFlowState.EMAIL_VERIFICATION,
        "email_otp": CamoufoxFlowState.EMAIL_VERIFICATION,
        "signup-password": CamoufoxFlowState.SIGNUP_PASSWORD,
        "login-password": CamoufoxFlowState.LOGIN_PASSWORD,
        # Consent is kept separate from the profile form.  The auth service
        # can render a second terms/authorization page after the about-you
        # submission, so callers must be able to record that boundary rather
        # than collapsing it into ``unknown`` or ``oauth_callback``.
        "profile-consent": CamoufoxFlowState.CONSENT,
        "profile_consent": CamoufoxFlowState.CONSENT,
        "consent-required": CamoufoxFlowState.CONSENT,
        "consent_required": CamoufoxFlowState.CONSENT,
        "oauth-consent": CamoufoxFlowState.CONSENT,
        "oauth_consent": CamoufoxFlowState.CONSENT,
        "sign_in_with_chatgpt_codex_consent": CamoufoxFlowState.CONSENT,
        "oauth": CamoufoxFlowState.OAUTH_CALLBACK,
        "callback": CamoufoxFlowState.OAUTH_CALLBACK,
        "challenge": CamoufoxFlowState.SECURITY,
        "external": CamoufoxFlowState.EXTERNAL_AUTH,
    }
    if candidate in aliases:
        return aliases[candidate]
    try:
        return CamoufoxFlowState(candidate)
    except ValueError:
        return CamoufoxFlowState.UNKNOWN


def _as_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    if isinstance(value, (int, float)):
        return bool(value)
    text = str(value).strip().casefold()
    if text in {"", "none"}:
        return default
    if text in {"0", "false", "no", "off", "disabled"}:
        return False
    if text in {"1", "true", "yes", "on", "enabled"}:
        return True
    return default


@dataclass(frozen=True, slots=True)
class CamoufoxRegistrationRequest:
    """Non-secret registration inputs passed to a browser runner.

    Password is marked ``repr=False`` so accidentally logging a request does
    not expose it.  Callers should still avoid serializing this object into a
    diagnostic event.
    """

    email: str
    proxy: str = ""
    task_id: str = ""
    batch_id: str = ""
    password: str = field(default="", repr=False)
    existing_password: str = field(default="", repr=False)
    force_existing_login: bool = False
    password_retry: bool = False
    password_retry_token: str = field(default="", repr=False)
    expected_exit_ip: str = ""
    # Continuation attempts need the previously persisted private result for
    # token/password eligibility checks.  Keep it out of repr/public
    # projections; the runner only holds this mapping for the call lifetime.
    prior_result: Mapping[str, Any] = field(default_factory=dict, repr=False, compare=False)

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "CamoufoxRegistrationRequest":
        """Build a request from a manager task without retaining the mapping."""

        retry_requested = _as_bool(value.get("password_retry", False))
        existing_login = _as_bool(
            value.get("force_existing_login", value.get("twofa_retry", False))
        )
        # Normal signup requests do not need the prior account envelope.  Do
        # not retain an incidental ``result`` payload unless this is an
        # explicit continuation/login request.
        prior = value.get("prior_result") if (retry_requested or existing_login) else {}
        if not isinstance(prior, Mapping) and (retry_requested or existing_login):
            prior = value.get("result")
        if not isinstance(prior, Mapping):
            prior = {}

        return cls(
            email=str(value.get("email") or "").strip(),
            proxy=str(value.get("proxy") or "").strip(),
            task_id=str(value.get("task_id") or "").strip(),
            batch_id=str(value.get("batch_id") or "").strip(),
            password=str(value.get("password") or ""),
            existing_password=str(
                value.get("existing_password")
                or value.get("saved_password")
                or ""
            ),
            force_existing_login=existing_login,
            password_retry=retry_requested,
            password_retry_token=str(value.get("password_retry_token") or ""),
            expected_exit_ip=str(
                value.get("expected_exit_ip") or value.get("exit_ip") or ""
            ).strip(),
            prior_result=dict(prior),
        )

    def public_dict(self) -> dict[str, Any]:
        """Return metadata safe for diagnostics and status projections.

        Credentials, mailbox URLs and raw proxy values deliberately never
        cross this boundary.  The full request remains available to the
        runner in memory only.
        """

        email = self.email
        if "@" in email:
            local, _, domain = email.partition("@")
            email = (local[:1] + "***" if local else "***") + "@" + domain
        return {
            "task_id": self.task_id,
            "batch_id": self.batch_id,
            "email": email,
            "expected_exit_ip": self.expected_exit_ip,
            "force_existing_login": self.force_existing_login,
            "password_retry": self.password_retry,
        }

    def private_result_snapshot(self) -> dict[str, Any]:
        """Return a detached continuation envelope for the legacy adapter.

        This helper deliberately does not sanitize or persist values: callers
        use it only while invoking the in-memory runner.  Keeping the copy at
        the contract boundary prevents a mutable manager task mapping from
        being mutated by a retry adapter.
        """
        try:
            snapshot = copy.deepcopy(dict(self.prior_result))
        except Exception:
            # A custom mapping may contain an object that cannot be deep
            # copied; retain the boundary guarantee with a detached top-level
            # mapping rather than failing a continuation attempt here.
            snapshot = dict(self.prior_result)
        return snapshot


@dataclass(frozen=True, slots=True)
class CamoufoxFlowCheckpoint:
    """An immutable state observation suitable for timing/diagnostic hooks."""

    state: CamoufoxFlowState
    observed_at: float = field(default_factory=time.time)
    outcome: str = "entered"
    detail: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "state": self.state.value,
            "observed_at": self.observed_at,
            "outcome": self.outcome,
            **({"detail": self.detail} if self.detail else {}),
        }


@dataclass(slots=True)
class CamoufoxFlowContext:
    """Mutable, non-persistent execution context owned by one task."""

    request: CamoufoxRegistrationRequest
    started_at: float = field(default_factory=time.monotonic)
    deadline_monotonic: float | None = None
    state: CamoufoxFlowState = CamoufoxFlowState.UNKNOWN
    checkpoints: list[CamoufoxFlowCheckpoint] = field(default_factory=list)

    def expired(self, now: float | None = None) -> bool:
        if self.deadline_monotonic is None:
            return False
        current = time.monotonic() if now is None else float(now)
        return current >= self.deadline_monotonic

    def observe(
        self,
        state: CamoufoxFlowState | str,
        *,
        outcome: str = "entered",
        detail: str = "",
        observed_at: float | None = None,
    ) -> CamoufoxFlowCheckpoint:
        normalized = normalize_flow_state(state)
        checkpoint = CamoufoxFlowCheckpoint(
            state=normalized,
            observed_at=time.time() if observed_at is None else float(observed_at),
            outcome=str(outcome or "entered")[:80],
            detail=str(detail or "")[:240],
        )
        self.state = normalized
        self.checkpoints.append(checkpoint)
        return checkpoint


@dataclass(frozen=True, slots=True)
class CamoufoxRegistrationResult:
    """Minimal result envelope used by adapters before manager enrichment."""

    driver: str = "camoufox"
    email: str = ""
    success: bool = False
    state: CamoufoxFlowState = CamoufoxFlowState.UNKNOWN
    error_code: str = ""
    retryable: bool = False
    fields: Mapping[str, Any] = field(default_factory=dict, repr=False)

    def as_dict(self) -> dict[str, Any]:
        result = dict(self.fields)
        result.update({
            "driver": self.driver,
            "email": self.email,
            "success": self.success,
            "state": self.state.value,
        })
        if self.error_code:
            result["error_code"] = self.error_code
        result["retryable"] = self.retryable
        return result

    def public_dict(self) -> dict[str, Any]:
        """Return a deliberately small status projection without secrets."""

        return {
            "driver": self.driver,
            "email": _mask_email(self.email),
            "success": self.success,
            "state": self.state.value,
            "error_code": self.error_code,
            "retryable": self.retryable,
        }


def _mask_email(value: Any) -> str:
    text = str(value or "")
    local, separator, domain = text.partition("@")
    if not separator:
        return ""
    return (local[:1] + "***" if local else "***") + "@" + domain


_POOL_SESSION_FIELDS = (
    "session_id", "task_id", "node_code", "node_label", "error_code",
    "page_type", "safe_page", "proxy_fingerprint", "artifact_id",
    "incident_id", "created_at",
)
_SESSION_EMAIL_RE = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
_SESSION_SECRET_RE = re.compile(
    r"(?i)\b(?:access[_ -]?token|refresh[_ -]?token|id[_ -]?token|"
    r"password|cookie|secret|authorization|otp|code)\s*[:=]\s*[^\s,;]+"
)


def _safe_session_text(value: Any, *, limit: int = 240) -> str:
    """Bound a pool-session label without turning it into a secret channel."""
    text = str(value or "").strip()
    text = _SESSION_EMAIL_RE.sub("<邮箱>", text)
    text = _SESSION_SECRET_RE.sub("<已隐藏>", text)
    return text[:max(0, int(limit))]


def _safe_session_page(value: Any) -> str:
    """Keep only trusted origin/path for public browser-pool snapshots."""
    try:
        parsed = urlsplit(str(value or ""))
        host = (parsed.hostname or "").casefold()
        if not parsed.scheme or not host:
            return ""
        trusted = host == "chatgpt.com" or host.endswith(".chatgpt.com")
        trusted = trusted or host == "openai.com" or host.endswith(".openai.com")
        if not trusted:
            return "页面地址未知"
        path = parsed.path or "/"
        path = _SESSION_EMAIL_RE.sub("<邮箱>", path)
        path = re.sub(r"(?<!\d)\+?\d{8,15}(?!\d)", "<手机号>", path)
        return f"{parsed.scheme.lower()}://{host}{path}"[:500]
    except (TypeError, ValueError):
        return ""


def _public_pool_session(value: Mapping[str, Any]) -> dict[str, Any]:
    """Whitelist a legacy pool session before it reaches status/API callers."""
    result: dict[str, Any] = {}
    for key in _POOL_SESSION_FIELDS:
        raw = value.get(key)
        if key == "safe_page":
            result[key] = _safe_session_page(raw)
        elif key == "created_at":
            try:
                number = float(raw)
                if math.isfinite(number) and 0 <= number <= 4_102_444_800:
                    result[key] = number
            except (TypeError, ValueError, OverflowError):
                pass
        else:
            result[key] = _safe_session_text(raw)
    return result


@dataclass(frozen=True, slots=True)
class CamoufoxPoolSnapshot:
    """Secret-free pool status used by the API/debug panel."""

    enabled: bool = False
    headless: bool = True
    capacity: int = 0
    used: int = 0
    browser_count: int = 0
    pool_count: int = 0
    open_contexts: int = 0
    closing_contexts: int = 0
    sessions: tuple[Mapping[str, Any], ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "headless": self.headless,
            "capacity": self.capacity,
            "used": self.used,
            "available": max(0, self.capacity - self.used),
            "browser_count": self.browser_count,
            "pool_count": self.pool_count,
            "open_contexts": self.open_contexts,
            "closing_contexts": self.closing_contexts,
            "sessions": [
                _public_pool_session(item) for item in self.sessions
                if isinstance(item, Mapping)
            ],
        }


__all__ = [
    "CamoufoxFlowCheckpoint",
    "CamoufoxFlowContext",
    "CamoufoxFlowState",
    "CamoufoxPoolSnapshot",
    "CamoufoxRegistrationRequest",
    "CamoufoxRegistrationResult",
    "TERMINAL_FLOW_STATES",
    "normalize_flow_state",
]
