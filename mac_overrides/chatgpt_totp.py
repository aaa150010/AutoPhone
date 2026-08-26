"""ChatGPT TOTP mailbox and transport patches for the recovered runtime."""

from __future__ import annotations

import base64
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import hmac
import json
import re
import struct
import threading
import time
from typing import Any, Callable, Iterator
from urllib.parse import urlsplit

try:
    from .mailbox_url_runtime import parse_mailbox_url_row
except ImportError:  # Loaded as a top-level override module by the Mac launcher.
    from mailbox_url_runtime import parse_mailbox_url_row

try:
    from .mailbox_password_url_rows import (
        parse_mailbox_password_url_row,
        parse_mailbox_password_url_totp_row,
    )
except ImportError:  # Loaded as a top-level override module by the Mac launcher.
    from mailbox_password_url_rows import (  # type: ignore[no-redef]
        parse_mailbox_password_url_row,
        parse_mailbox_password_url_totp_row,
    )

try:
    from .plain_mailbox_rows import (
        parse_plain_password_mailbox_row,
        plain_password_identity,
    )
except ImportError:  # Loaded as a top-level override module by the Mac launcher.
    from plain_mailbox_rows import (
        parse_plain_password_mailbox_row,
        plain_password_identity,
    )


_EMAIL_PATTERN = re.compile(
    r"(?i)[a-z0-9][a-z0-9._%+-]*@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}"
)
_TOTP_SEPARATOR_PATTERNS = tuple(
    re.compile(pattern)
    for pattern in (
        r"[\-\u2010\u2011\u2012\u2013\u2014\u2015\u2212\ufe58\ufe63\uff0d]{2,}",
        r"\|+",
        r"\t+",
        r",+",
        r";+",
        r":+",
        r"｜+",
        r"，+",
        r"；+",
        r"：+",
    )
)
_SAFE_TOTP_PROVIDER_CODES = frozenset(
    {
        "incorrect_code",
        "invalid_authorization_step",
        "mfa_authorization_step_expired",
        "oauth_session_invalid",
        "mfa_factor_id_missing",
    }
)
_SAFE_PROVIDER_CODE = re.compile(r"^[a-z][a-z0-9_.-]{1,95}$")
_SENSITIVE_PROVIDER_CODE_MARKERS = (
    "token",
    "secret",
    "password",
    "cookie",
    "authorization",
    "bearer",
)


def _normalize_totp_secret(secret: Any) -> str:
    value = str(secret or "").strip()
    if not value:
        return ""
    label = re.match(r"(?i)^(?:2fa|totp|secret|密钥)\s*[=:：]\s*(.+)$", value)
    if label:
        value = label.group(1).strip()
    normalized = re.sub(r"[\s-]+", "", value).upper()
    if not re.fullmatch(r"[A-Z2-7]+=*", normalized):
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


def _parse_chatgpt_totp_row(raw: Any) -> tuple[str, str, str, str] | None:
    value = str(raw or "").strip()
    oauth_parts = [part.strip() for part in value.split("----")]
    if (
        len(oauth_parts) == 4
        and _EMAIL_PATTERN.fullmatch(oauth_parts[0])
    ):
        return None
    for pattern in _TOTP_SEPARATOR_PATTERNS:
        matches = list(pattern.finditer(value))
        if len(matches) < 2:
            continue
        first, second = matches[0], matches[-1]
        email = value[: first.start()].strip()
        password = value[first.end() : second.start()].strip()
        totp_secret = _normalize_totp_secret(value[second.end() :])
        if _EMAIL_PATTERN.fullmatch(email) and password and totp_secret:
            return email.lower(), password, totp_secret, first.group(0)
    return None


def parse_chatgpt_totp_row(raw: Any) -> tuple[str, str, str] | None:
    parsed = _parse_chatgpt_totp_row(raw)
    return parsed[:3] if parsed is not None else None


def parse_mailbox_url_totp_row(raw: Any) -> tuple[str, str, str] | None:
    parts = [part.strip() for part in str(raw or "").strip().split("----")]
    if len(parts) != 3:
        return None
    email, mailbox_url = parts[0].lower(), parts[1]
    totp_secret = _normalize_totp_secret(parts[2])
    parsed_url = parse_mailbox_url_row(f"{email}|{mailbox_url}")
    if parsed_url is None or not totp_secret:
        return None
    return parsed_url.email, parsed_url.mailbox_url, totp_secret


def masked_chatgpt_totp_row(raw: Any, mask: str = "***") -> str:
    parsed = _parse_chatgpt_totp_row(raw)
    if parsed is None:
        return ""
    email, _password, _totp_secret, delimiter = parsed
    return delimiter.join((email, mask, mask))


def masked_mailbox_url_totp_row(raw: Any, mask: str = "***") -> str:
    parsed = parse_mailbox_url_totp_row(raw)
    if parsed is None:
        return ""
    email, _mailbox_url, _totp_secret = parsed
    return "----".join((email, mask, mask))


def mailbox_credential_identity(
    row: Any,
    parse_oauth_mailbox_row: Callable[[Any], tuple[str, str, str, str] | None],
) -> tuple[str, str]:
    """Return the recovered pool identity without depending on row formatting."""

    raw = str(row or "").strip()
    parsed_password_url_totp = parse_mailbox_password_url_totp_row(raw)
    if parsed_password_url_totp is not None:
        return (
            parsed_password_url_totp.email,
            f"free:{parsed_password_url_totp.password}:{parsed_password_url_totp.mailbox_url}:{parsed_password_url_totp.totp_secret}",
        )
    parsed_password_url = parse_mailbox_password_url_row(raw)
    if parsed_password_url is not None:
        return (
            parsed_password_url.email,
            plain_password_identity(parsed_password_url.email, parsed_password_url.password),
        )
    parsed_oauth = parse_oauth_mailbox_row(raw)
    if parsed_oauth is not None:
        email, password, client_id, refresh_token = parsed_oauth
        return email, f"outlook:{client_id}:{refresh_token or password}"
    parsed_url_totp = parse_mailbox_url_totp_row(raw)
    if parsed_url_totp is not None:
        email, mailbox_url, secret = parsed_url_totp
        return email, f"url:{mailbox_url}:totp:{secret}"
    parsed_totp = parse_chatgpt_totp_row(raw)
    if parsed_totp is not None:
        email, _password, secret = parsed_totp
        return email, f"outlook:chatgpt_totp:{secret}"
    parsed_url = parse_mailbox_url_row(raw)
    if parsed_url is not None:
        return parsed_url.email, f"url:{parsed_url.mailbox_url}"
    parsed_plain = parse_plain_password_mailbox_row(raw)
    if parsed_plain is not None:
        email, password, _delimiter = parsed_plain
        return email, plain_password_identity(email, password)
    return "", raw


def totp_code(secret: Any, *, now: float | None = None, digits: int = 6, period: int = 30) -> str:
    normalized = _normalize_totp_secret(secret)
    if not normalized:
        raise ValueError("2FA 密钥为空或格式无效")
    normalized += "=" * ((8 - len(normalized) % 8) % 8)
    key = base64.b32decode(normalized, casefold=True)
    counter = int((time.time() if now is None else now) // period)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(value % (10**digits)).zfill(digits)


def refresh_transport_totp_payload(
    transport: Any,
    flow: Any,
    *,
    now_fn: Callable[[], float] | None = None,
    sleep_fn: Callable[[float], None] | None = None,
) -> bool:
    """Refresh a pending MFA payload after Sentinel headers are ready."""
    if str(flow or "") != "mfa_otp_verify":
        return False
    payload = getattr(transport, "_gptphone_totp_payload", None)
    secret = str(getattr(transport, "_gptphone_totp_secret", "") or "")
    if not isinstance(payload, dict) or not secret:
        return False
    now_fn = now_fn or time.time
    sleep_fn = sleep_fn or time.sleep
    now = float(now_fn())
    remaining = 30.0 - (now % 30.0)
    if remaining < 5.0:
        sleep_fn(remaining + 0.05)
        now = float(now_fn())
    payload["code"] = totp_code(secret, now=now)
    return True


@contextmanager
def pending_transport_totp_payload(
    transport: Any,
    payload: dict[str, Any],
    secret: Any,
) -> Iterator[dict[str, Any]]:
    """Expose a TOTP payload only for the request whose headers refresh it."""
    missing = object()
    previous_payload = getattr(transport, "_gptphone_totp_payload", missing)
    previous_secret = getattr(transport, "_gptphone_totp_secret", missing)
    setattr(transport, "_gptphone_totp_payload", payload)
    setattr(transport, "_gptphone_totp_secret", _normalize_totp_secret(secret))
    try:
        yield payload
    finally:
        if previous_payload is missing:
            try:
                delattr(transport, "_gptphone_totp_payload")
            except AttributeError:
                pass
        else:
            setattr(transport, "_gptphone_totp_payload", previous_payload)
        if previous_secret is missing:
            try:
                delattr(transport, "_gptphone_totp_secret")
            except AttributeError:
                pass
        else:
            setattr(transport, "_gptphone_totp_secret", previous_secret)


def _call_log(log_fn: Any, message: str, level: str = "info") -> None:
    if not callable(log_fn):
        return
    try:
        log_fn(message, level)
    except TypeError as exc:
        if "positional argument" not in str(exc) and "arguments" not in str(exc):
            raise
        log_fn(message)


@dataclass(frozen=True)
class ChatGptTotpPatchSet:
    entries_unlocked: Callable[..., Any]
    outlook_otp_provider: Callable[..., Any]
    account_label: Callable[..., Any]
    verify_password: Callable[..., Any]
    send_mfa_otp: Callable[..., Any]
    verify_mfa_otp: Callable[..., Any]
    reset_task_state: Callable[[], None]


def build_chatgpt_totp_patches(
    *,
    runtime_module: Any,
    codex_oauth_chain: Any,
    original_entries_unlocked: Callable[..., Any],
    original_outlook_otp_provider: Callable[..., Any],
    original_account_label: Callable[..., Any],
    original_verify_password: Callable[..., Any],
    original_send_mfa_otp: Callable[..., Any],
    original_verify_mfa_otp: Callable[..., Any],
    parse_oauth_mailbox_row: Callable[[Any], tuple[str, str, str, str] | None],
) -> ChatGptTotpPatchSet:
    """Build plain callables that preserve the recovered method signatures."""
    active_state = threading.local()

    def is_active() -> bool:
        return time.time() < float(getattr(active_state, "until", 0.0) or 0.0)

    def activate(seconds: int = 600) -> None:
        active_state.until = max(
            float(getattr(active_state, "until", 0.0) or 0.0),
            time.time() + seconds,
        )

    def remember_totp_secret(secret: Any) -> None:
        active_state.totp_secret = _normalize_totp_secret(secret)

    def reset_task_state() -> None:
        active_state.until = 0.0
        active_state.totp_secret = ""
        active_state.rejected_totp_code = ""

    def page_type(response: Any) -> str:
        try:
            return codex_oauth_chain._page_type(response)
        except Exception:
            page = response.get("page") if isinstance(response, dict) else None
            return page.get("type") if isinstance(page, dict) else ""

    def continue_url(response: Any) -> str:
        try:
            return codex_oauth_chain._continue_url(response)
        except Exception:
            return str(response.get("continue_url") or "") if isinstance(response, dict) else ""

    def response_error(response: Any) -> str:
        if not isinstance(response, dict):
            return ""
        error = response.get("error") or response.get("message") or ""
        if isinstance(error, dict):
            return str(error.get("code") or error.get("message") or "")
        return str(error)

    def safe_response_error(response: Any) -> str:
        error = response.get("error") if isinstance(response, dict) else None
        explicit_code = ""
        if isinstance(error, dict):
            explicit_code = str(error.get("code") or error.get("type") or "")
        for candidate in (explicit_code, response_error(response)):
            raw = candidate.strip().lower().replace(" ", "_")
            if not raw:
                continue
            if raw in _SAFE_TOTP_PROVIDER_CODES:
                return raw
            if (
                _SAFE_PROVIDER_CODE.fullmatch(raw)
                and not any(marker in raw for marker in _SENSITIVE_PROVIDER_CODE_MARKERS)
            ):
                return raw
        return "provider_error" if response_error(response).strip() else ""

    def remember_post_auth_continue(transport: Any, response: Any) -> None:
        next_url = continue_url(response)
        if not next_url:
            return
        setattr(transport, "_gptphone_auth_continue_url", next_url)
        setattr(transport, "_chatgpt_totp_mfa_continue_url", "")

    def factor_id_from(response: Any) -> str:
        if not isinstance(response, dict):
            return ""
        page = response.get("page") if isinstance(response.get("page"), dict) else {}
        payload = page.get("payload") if isinstance(page.get("payload"), dict) else {}
        factor_id = str(payload.get("factor_id") or "").strip()
        if factor_id:
            return factor_id
        for key in ("mfa_challenge_factors", "mfa_factors"):
            factors = response.get(key)
            if not isinstance(factors, list):
                auth = response.get("oai-client-auth-session")
                factors = auth.get(key) if isinstance(auth, dict) else None
            if not isinstance(factors, list):
                continue
            for factor in factors:
                if isinstance(factor, dict) and factor.get("factor_type") == "totp":
                    factor_id = str(factor.get("id") or "").strip()
                    if factor_id:
                        return factor_id
        match = re.search(r"/mfa-challenge/([^/?#]+)", continue_url(response))
        return match.group(1) if match else ""

    def trace(transport: Any, step: str, endpoint: str, response: Any, **extra: Any) -> None:
        if not callable(getattr(transport, "log_fn", None)):
            return
        try:
            continue_path = urlsplit(continue_url(response) or "").path or "-"
        except (TypeError, ValueError):
            continue_path = "-"
        parts = [
            f"endpoint={endpoint}",
            f"_status={int(response.get('_status') or 0) if isinstance(response, dict) else 0}",
            f"page_type={page_type(response) or '-'}",
            f"continue_path={continue_path}",
            f"error={safe_response_error(response) or '-'}",
        ]
        parts.extend(f"{key}={value if value else '-'}" for key, value in extra.items())
        _call_log(transport.log_fn, f"  [CodexTOTP] {step} " + " ".join(parts), "info")

    def patched_verify_password(transport: Any, password: str) -> Any:
        response = original_verify_password(transport, password)
        factor_id = factor_id_from(response)
        if factor_id:
            setattr(transport, "_chatgpt_totp_factor_id", factor_id)
        next_url = continue_url(response)
        if next_url:
            setattr(transport, "_chatgpt_totp_mfa_continue_url", next_url)
        totp_flow = is_active()
        # The provider is created on a reusable worker thread. Consume the
        # thread-local activation at the password boundary so another task
        # cannot inherit a previous mailbox's TOTP flow.
        active_state.until = 0.0
        active_state.rejected_totp_code = ""
        setattr(transport, "_gptphone_totp_flow", totp_flow)
        setattr(transport, "_gptphone_totp_incorrect_retries", 0)
        if totp_flow:
            secret = str(getattr(active_state, "totp_secret", "") or "")
            if secret:
                setattr(transport, "_gptphone_totp_secret", secret)
        active_state.totp_secret = ""
        if totp_flow:
            trace(
                transport,
                "password_verify",
                "/api/accounts/password/verify",
                response,
                factor_id_present="1" if factor_id else "0",
            )
        return response

    def patched_send_mfa_otp(transport: Any, next_url: str) -> Any:
        if not getattr(transport, "_gptphone_totp_flow", False):
            return original_send_mfa_otp(transport, next_url)
        if next_url:
            setattr(transport, "_chatgpt_totp_mfa_continue_url", next_url)
            match = re.search(r"/mfa-challenge/([^/?#]+)", str(next_url))
            if match and not getattr(transport, "_chatgpt_totp_factor_id", ""):
                setattr(transport, "_chatgpt_totp_factor_id", match.group(1))
        factor_id = str(getattr(transport, "_chatgpt_totp_factor_id", "") or "").strip()
        if not factor_id:
            response = {
                "_status": 400,
                "page": {"type": "mfa_challenge"},
                "error": {"code": "mfa_factor_id_missing", "message": "TOTP factor id missing"},
            }
            trace(transport, "mfa_issue_challenge", "/api/accounts/mfa/issue_challenge", response)
            return response

        response = transport._post_auth_json(
            "/api/accounts/mfa/issue_challenge",
            {"id": factor_id, "type": "totp", "force_fresh_challenge": False},
            flow="mfa_otp_issue",
            referer=f"{codex_oauth_chain.AUTH}/log-in/password",
            timeout=30,
        )
        if not isinstance(response, dict):
            response = {"_status": 200}
        response = dict(response)
        response.setdefault("_status", 200)
        response.setdefault("page", {"type": "mfa_challenge"})
        response.setdefault(
            "continue_url",
            next_url or getattr(transport, "_chatgpt_totp_mfa_continue_url", ""),
        )
        trace(
            transport,
            "mfa_issue_challenge",
            "/api/accounts/mfa/issue_challenge",
            response,
            force_fresh_challenge="0",
        )
        return response

    def patched_verify_mfa_otp(transport: Any, code: str) -> Any:
        if not getattr(transport, "_gptphone_totp_flow", False):
            response = original_verify_mfa_otp(transport, code)
            remember_post_auth_continue(transport, response)
            return response
        factor_id = str(getattr(transport, "_chatgpt_totp_factor_id", "") or "").strip()
        if not factor_id:
            next_url = str(getattr(transport, "_chatgpt_totp_mfa_continue_url", "") or "")
            match = re.search(r"/mfa-challenge/([^/?#]+)", next_url)
            factor_id = match.group(1) if match else ""
        if not factor_id:
            response = {
                "_status": 400,
                "page": {"type": "mfa_challenge"},
                "error": {"code": "mfa_factor_id_missing", "message": "TOTP factor id missing"},
            }
            trace(transport, "mfa_verify", "/api/accounts/mfa/verify", response)
            return response
        payload = {"id": factor_id, "type": "totp", "code": code}
        secret = getattr(transport, "_gptphone_totp_secret", "")
        try:
            with pending_transport_totp_payload(transport, payload, secret):
                if not getattr(transport, "_gptphone_totp_refresh_in_headers", False):
                    refresh_transport_totp_payload(transport, "mfa_otp_verify")
                response = transport._post_auth_json(
                    "/api/accounts/mfa/verify",
                    payload,
                    flow="mfa_otp_verify",
                    referer=f"{codex_oauth_chain.AUTH}/mfa-challenge/{factor_id}",
                    timeout=30,
                )
        except BaseException:
            setattr(transport, "_gptphone_totp_flow", False)
            setattr(transport, "_gptphone_totp_secret", "")
            setattr(transport, "_gptphone_totp_incorrect_retries", 0)
            active_state.until = 0.0
            active_state.rejected_totp_code = ""
            raise
        error_code = response_error(response).strip().lower()
        retry_count = int(
            getattr(transport, "_gptphone_totp_incorrect_retries", 0) or 0
        )
        keep_challenge = error_code == "incorrect_code" and retry_count < 1
        if keep_challenge:
            # The recovered chain retries an incorrect TOTP once. Keep the
            # same factor and secret, but remember the code that actually
            # reached the provider so wait_code cannot submit it again.
            setattr(transport, "_gptphone_totp_flow", True)
            setattr(transport, "_gptphone_totp_incorrect_retries", retry_count + 1)
            active_state.rejected_totp_code = str(payload.get("code") or code or "")
        else:
            if error_code == "incorrect_code" and secret:
                # Keep a task-local copy for the explicit manual fallback;
                # it is cleared when the task wrapper resets its state.
                setattr(transport, "_gptphone_totp_manual_secret", secret)
            setattr(transport, "_gptphone_totp_flow", False)
            setattr(transport, "_gptphone_totp_secret", "")
            setattr(transport, "_gptphone_totp_incorrect_retries", 0)
            active_state.until = 0.0
            active_state.rejected_totp_code = ""
        trace(
            transport,
            "mfa_verify",
            "/api/accounts/mfa/verify",
            response,
            factor_id_present="1",
        )
        remember_post_auth_continue(transport, response)
        return response

    def patched_entries_unlocked(pool_self: Any) -> Any:
        entries, errors = original_entries_unlocked(pool_self)
        try:
            raw_lines = pool_self.pool_path.read_text(encoding="utf-8-sig").splitlines()
        except FileNotFoundError:
            raw_lines = []

        existing_by_line = {
            int(getattr(entry, "line_no", 0) or 0): entry
            for entry in entries
            if int(getattr(entry, "line_no", 0) or 0) > 0
        }
        pool_state = _read_pool_state(pool_self)
        state_keys = _pool_state_keys(pool_state)
        state_changed = False

        def compatible_key(
            email: str,
            identity: str,
            raw: str,
            line_no: int,
            equivalent_rows: tuple[str, ...] = (),
        ) -> str:
            nonlocal state_changed, state_keys
            canonical, changed = _migrate_entry_state(
                runtime_module,
                email,
                identity,
                raw,
                line_no,
                pool_state,
                equivalent_rows,
            )
            state_changed = state_changed or changed
            state_keys = _pool_state_keys(pool_state)
            return canonical

        replacements = {}
        identities: dict[int, str] = {}
        for line_no, raw in enumerate(raw_lines, start=1):
            raw = raw.strip()
            parsed_password_url = parse_mailbox_password_url_row(raw)
            parsed_oauth = parse_oauth_mailbox_row(raw)
            parsed_url_totp = parse_mailbox_url_totp_row(raw)
            parsed_totp = parse_chatgpt_totp_row(raw)
            parsed_url = parse_mailbox_url_row(raw)
            parsed_plain = parse_plain_password_mailbox_row(raw)
            if parsed_password_url:
                email = parsed_password_url.email
                password = parsed_password_url.password
                mailbox_url = parsed_password_url.mailbox_url
                identity = plain_password_identity(email, password)
                entry_key = compatible_key(
                    email,
                    identity,
                    raw,
                    line_no,
                    _plain_password_legacy_rows(raw, email, password),
                )
                replacements[line_no] = runtime_module.PoolEntry(
                    email=email,
                    mailbox_url=mailbox_url,
                    line_no=line_no,
                    key=entry_key,
                    mailbox_type="url",
                    password=password,
                    oauth_client_id="",
                    oauth_refresh_token="",
                    source_row=raw,
                )
                identities[line_no] = identity
            elif parsed_oauth:
                email, password, oauth_client_id, oauth_refresh_token = parsed_oauth
                identity = f"outlook:{oauth_client_id}:{oauth_refresh_token or password}"
                entry_key = compatible_key(email, identity, raw, line_no)
                current = existing_by_line.get(line_no)
                if (
                    current is not None
                    and str(getattr(current, "oauth_client_id", "") or "") == oauth_client_id
                    and str(getattr(current, "oauth_refresh_token", "") or "") == oauth_refresh_token
                    and _can_reuse_entry_key(
                        runtime_module, current, email, identity, raw, state_keys
                    )
                ):
                    identities[line_no] = identity
                    continue
                replacements[line_no] = runtime_module.PoolEntry(
                    email=email,
                    mailbox_url="",
                    line_no=line_no,
                    key=entry_key,
                    mailbox_type="outlook_oauth",
                    password=password,
                    oauth_client_id=oauth_client_id,
                    oauth_refresh_token=oauth_refresh_token,
                    source_row=raw,
                )
                identities[line_no] = identity
            elif parsed_url_totp:
                email, mailbox_url, totp_secret = parsed_url_totp
                identity = f"url:{mailbox_url}:totp:{totp_secret}"
                entry_key = compatible_key(email, identity, raw, line_no)
                replacements[line_no] = runtime_module.PoolEntry(
                    email=email,
                    mailbox_url=mailbox_url,
                    line_no=line_no,
                    key=entry_key,
                    mailbox_type="url",
                    password="",
                    oauth_client_id="chatgpt_totp",
                    oauth_refresh_token=totp_secret,
                    source_row=raw,
                )
                identities[line_no] = identity
            elif parsed_totp:
                email, password, totp_secret = parsed_totp
                identity = f"outlook:chatgpt_totp:{totp_secret}"
                entry_key = compatible_key(email, identity, raw, line_no)
                replacements[line_no] = runtime_module.PoolEntry(
                    email=email,
                    mailbox_url="",
                    line_no=line_no,
                    key=entry_key,
                    mailbox_type="outlook_password",
                    password=password,
                    oauth_client_id="chatgpt_totp",
                    oauth_refresh_token=totp_secret,
                    source_row=raw,
                )
                identities[line_no] = identity
            elif parsed_url:
                current = existing_by_line.get(line_no)
                identity = f"url:{parsed_url.mailbox_url}"
                entry_key = compatible_key(
                    parsed_url.email, identity, raw, line_no
                )
                if (
                    current is not None
                    and str(getattr(current, "mailbox_url", "") or "")
                    == parsed_url.mailbox_url
                    and _can_reuse_entry_key(
                        runtime_module,
                        current,
                        parsed_url.email,
                        identity,
                        raw,
                        state_keys,
                    )
                ):
                    identities[line_no] = identity
                    continue
                replacements[line_no] = runtime_module.PoolEntry(
                    email=parsed_url.email,
                    mailbox_url=parsed_url.mailbox_url,
                    line_no=line_no,
                    key=entry_key,
                    mailbox_type="url",
                    password="",
                    oauth_client_id="",
                    oauth_refresh_token="",
                    source_row=raw,
                )
                identities[line_no] = identity
            elif parsed_plain:
                email, password, _delimiter = parsed_plain
                identity = plain_password_identity(email, password)
                entry_key = compatible_key(
                    email,
                    identity,
                    raw,
                    line_no,
                    _plain_password_legacy_rows(raw, email, password),
                )
                current = existing_by_line.get(line_no)
                if (
                    current is not None
                    and str(getattr(current, "email", "") or "").strip().lower() == email
                    and str(getattr(current, "password", "") or "") == password
                    and not str(getattr(current, "oauth_client_id", "") or "")
                    and _can_reuse_entry_key(
                        runtime_module, current, email, identity, raw, state_keys
                    )
                ):
                    identities[line_no] = identity
                    continue
                replacements[line_no] = runtime_module.PoolEntry(
                    email=email,
                    mailbox_url="",
                    line_no=line_no,
                    key=entry_key,
                    mailbox_type="outlook_password",
                    password=password,
                    oauth_client_id="",
                    oauth_refresh_token="",
                    source_row=raw,
                )
                identities[line_no] = identity

        replaced_lines = set(replacements)
        errors = [
            error
            for error in errors
            if not any(str(error).startswith(f"line {line_no}:") for line_no in replaced_lines)
        ]
        patched = [replacements.get(getattr(entry, "line_no", 0), entry) for entry in entries]
        existing_lines = {getattr(entry, "line_no", 0) for entry in patched}
        patched.extend(entry for line_no, entry in replacements.items() if line_no not in existing_lines)
        patched.sort(key=lambda entry: getattr(entry, "line_no", 0))
        deduplicated = []
        seen_identities: set[tuple[str, str]] = set()
        for entry in patched:
            line_no = int(getattr(entry, "line_no", 0) or 0)
            identity = identities.get(line_no) or _entry_identity(entry)
            marker = (str(getattr(entry, "email", "") or "").strip().lower(), identity)
            if identity and marker in seen_identities:
                errors.append(f"line {line_no}: duplicate mailbox row")
                continue
            if identity:
                seen_identities.add(marker)
            deduplicated.append(entry)
        if state_changed and pool_state is not None:
            _write_pool_state(pool_self, pool_state)
        return deduplicated, errors

    class ChatGptTotpOtpProvider:
        def __init__(
            self,
            entry: Any,
            _config: Any,
            log_fn: Any,
            *,
            phase_gate: Any = None,
            stop_event: Any = None,
            task_id: str = "",
            state_fn: Any = None,
        ) -> None:
            self.entry = entry
            self.log_fn = log_fn
            self.stop_event = stop_event
            self.task_id = task_id
            self.state_fn = state_fn
            self.phase_gate = phase_gate
            self.sent_at = 0.0
            remember_totp_secret(getattr(entry, "oauth_refresh_token", ""))
            activate()

        def acquire_login_slot(self):
            return None

        def mark_sent(self):
            remember_totp_secret(getattr(self.entry, "oauth_refresh_token", ""))
            activate()
            self.sent_at = time.time()

        def mark_verified(self):
            return None

        def wait_code(self, _email):
            if self.stop_event is not None and self.stop_event.is_set():
                return ""
            secret = getattr(self.entry, "oauth_refresh_token", "")
            remember_totp_secret(secret)
            waiting_logged = False
            while True:
                now = time.time()
                code = totp_code(secret, now=now)
                rejected_code = str(
                    getattr(active_state, "rejected_totp_code", "") or ""
                )
                if not rejected_code or code != rejected_code:
                    active_state.rejected_totp_code = ""
                    break
                if not waiting_logged:
                    _call_log(
                        self.log_fn,
                        "  [Codex] 上一个 2FA 动态码已被拒绝，等待下一个时间窗口后重试",
                        "warn",
                    )
                    waiting_logged = True
                wait_seconds = 30.0 - (now % 30.0) + 0.05
                waiter = getattr(self.stop_event, "wait", None)
                if callable(waiter):
                    if waiter(wait_seconds):
                        return ""
                else:
                    time.sleep(wait_seconds)
                if self.stop_event is not None and self.stop_event.is_set():
                    return ""
            activate(120)
            _call_log(self.log_fn, "  [Codex] 已根据 2FA 密钥生成临时验证码", "info")
            return code

        def close(self):
            return None

    def patched_outlook_otp_provider(entry: Any, config: Any, log_fn: Any, **kwargs: Any) -> Any:
        if parse_chatgpt_totp_row(getattr(entry, "source_row", "")) or (
            getattr(entry, "oauth_client_id", "") == "chatgpt_totp"
            and getattr(entry, "oauth_refresh_token", "")
        ):
            return ChatGptTotpOtpProvider(entry, config, log_fn, **kwargs)
        return original_outlook_otp_provider(entry, config, log_fn, **kwargs)

    def patched_account_label(importer: Any, entry: Any) -> str:
        if getattr(entry, "oauth_client_id", "") == "chatgpt_totp":
            return getattr(entry, "email", "")
        try:
            return original_account_label(entry)
        except TypeError as exc:
            if "positional argument" not in str(exc):
                raise
            return original_account_label(importer, entry)

    return ChatGptTotpPatchSet(
        entries_unlocked=patched_entries_unlocked,
        outlook_otp_provider=patched_outlook_otp_provider,
        account_label=patched_account_label,
        verify_password=patched_verify_password,
        send_mfa_otp=patched_send_mfa_otp,
        verify_mfa_otp=patched_verify_mfa_otp,
        reset_task_state=reset_task_state,
    )


def _entry_key(runtime_module: Any, email: str, identity: str) -> str:
    mailbox_pool = getattr(runtime_module, "_mailbox_pool", None)
    if mailbox_pool is not None:
        return mailbox_pool._entry_key(email, identity)
    return hashlib.sha256(
        f"{str(email).strip().lower()}\x1f{identity}".encode("utf-8", "ignore")
    ).hexdigest()


def _legacy_entry_key(runtime_module: Any, email: str, raw: str) -> str:
    return next(iter(_legacy_entry_keys(runtime_module, email, raw)))


def _legacy_entry_keys(runtime_module: Any, email: str, raw: str) -> tuple[str, ...]:
    account = str(email or "").strip().lower()
    source = str(raw or "").strip()
    recovered = hashlib.sha256(
        f"{account}\x1f{source}".encode("utf-8", "ignore")
    ).hexdigest()
    fallback = hashlib.sha256(f"{account}\n{source}".encode()).hexdigest()
    keys = [recovered, fallback]
    mailbox_pool = getattr(runtime_module, "_mailbox_pool", None)
    if mailbox_pool is not None:
        keys.insert(0, mailbox_pool._entry_key(account, source))
    return tuple(dict.fromkeys(keys))


def _plain_password_legacy_rows(
    raw: str,
    email: str,
    password: str,
) -> tuple[str, ...]:
    parsed = parse_plain_password_mailbox_row(raw)
    raw_email = (
        str(raw).split(parsed[2], 1)[0].strip()
        if parsed is not None
        else str(email).strip()
    )
    rows = [str(raw).strip()]
    for account in dict.fromkeys((raw_email, email, str(email).upper())):
        rows.extend(f"{account}{delimiter}{password}" for delimiter in ("----", "--", "|"))
    return tuple(dict.fromkeys(rows))


def _compatible_entry_key(
    runtime_module: Any,
    email: str,
    identity: str,
    raw: str,
    state_keys: set[str],
) -> str:
    del raw, state_keys
    return _entry_key(runtime_module, email, identity)


def _can_reuse_entry_key(
    runtime_module: Any,
    entry: Any,
    email: str,
    identity: str,
    raw: str,
    state_keys: set[str],
) -> bool:
    expected = _compatible_entry_key(runtime_module, email, identity, raw, state_keys)
    return hmac.compare_digest(str(getattr(entry, "key", "") or ""), expected)


def _read_pool_state(pool_self: Any) -> dict[str, Any] | None:
    state_path = getattr(pool_self, "state_path", None)
    if state_path is None:
        return None
    try:
        value = json.loads(state_path.read_text(encoding="utf-8-sig"))
    except (AttributeError, FileNotFoundError, OSError, TypeError, ValueError):
        return None
    if not isinstance(value, dict) or not isinstance(value.get("items"), dict):
        return None
    return value


def _pool_state_keys(state: dict[str, Any] | None) -> set[str]:
    if state is None:
        return set()
    items = state.get("items")
    if not isinstance(items, dict):
        return set()
    return {str(key) for key in items}


def _state_precedence(item: dict[str, Any], now: float) -> tuple[int, float, float]:
    status = str(item.get("status") or "").strip().lower()
    try:
        lease_until = float(item.get("lease_until") or 0)
    except (TypeError, ValueError):
        lease_until = 0.0
    try:
        updated_at = float(item.get("updated_at") or 0)
    except (TypeError, ValueError):
        updated_at = 0.0
    if status in {"consumed", "damaged"}:
        rank = 3
    elif status == "leased" and lease_until > now:
        rank = 2
    else:
        rank = 1
    return rank, updated_at, lease_until


def _migrate_entry_state(
    runtime_module: Any,
    email: str,
    identity: str,
    raw: str,
    line_no: int,
    state: dict[str, Any] | None,
    equivalent_rows: tuple[str, ...] = (),
) -> tuple[str, bool]:
    canonical = _entry_key(runtime_module, email, identity)
    if state is None or not isinstance(state.get("items"), dict):
        return canonical, False

    items = state["items"]
    candidate_keys = {canonical}
    # Mailbox administration addresses the immutable source row directly,
    # while older pool state may still use an identity or raw-row key.  When
    # the exact source row exists, it is the authoritative state for this
    # physical row and must win over those historical aliases.
    source_row_id = hashlib.sha256(str(raw).strip().encode("utf-8")).hexdigest()
    candidate_keys.add(source_row_id)
    for source in dict.fromkeys((raw, *equivalent_rows)):
        candidate_keys.update(_legacy_entry_keys(runtime_module, email, source))
    normalized_email = str(email or "").strip().lower()
    candidates = [
        (key, items[key])
        for key in sorted(candidate_keys, key=lambda value: (value != canonical, value))
        if key in items and isinstance(items[key], dict)
    ]
    if not candidates or all(key == canonical for key, _item in candidates):
        return canonical, False

    now = time.time()
    selected = next(
        (item for key, item in candidates if key == source_row_id),
        None,
    )
    if selected is None:
        _selected_key, selected = max(
            candidates,
            key=lambda candidate: _state_precedence(candidate[1], now),
        )
    merged = dict(selected)
    history: list[Any] = []
    line_numbers = [line_no]
    for _key, item in candidates:
        try:
            candidate_line = int(item.get("line_no") or 0)
        except (TypeError, ValueError):
            candidate_line = 0
        if candidate_line > 0:
            line_numbers.append(candidate_line)
        for event in item.get("history") if isinstance(item.get("history"), list) else ():
            if event not in history:
                history.append(event)
    merged["email"] = normalized_email
    merged["line_no"] = min(number for number in line_numbers if number > 0)
    if history:
        merged["history"] = history
    for key, _item in candidates:
        if key != canonical:
            items.pop(key, None)
    items[canonical] = merged
    state["updated_at"] = int(now)
    return canonical, True


def _write_pool_state(pool_self: Any, state: dict[str, Any]) -> None:
    state_path = getattr(pool_self, "state_path", None)
    if state_path is None:
        return
    temporary = state_path.with_suffix(state_path.suffix + ".identity.tmp")
    temporary.touch(mode=0o600, exist_ok=True)
    temporary.chmod(0o600)
    temporary.write_text(
        json.dumps(state, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    temporary.replace(state_path)
    state_path.chmod(0o600)


def _entry_identity(entry: Any) -> str:
    mailbox_url = str(getattr(entry, "mailbox_url", "") or "")
    password = str(getattr(entry, "password", "") or "")
    if mailbox_url and password:
        return plain_password_identity(getattr(entry, "email", ""), password)
    if mailbox_url:
        return f"url:{mailbox_url}"
    client_id = str(getattr(entry, "oauth_client_id", "") or "")
    refresh_token = str(getattr(entry, "oauth_refresh_token", "") or "")
    if client_id == "chatgpt_totp" and refresh_token:
        return f"outlook:chatgpt_totp:{refresh_token}"
    if client_id or refresh_token:
        return f"outlook:{client_id}:{refresh_token or password}"
    return plain_password_identity(getattr(entry, "email", ""), password)
