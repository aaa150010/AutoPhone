"""ChatGPT TOTP mailbox and transport patches for the recovered runtime."""

from __future__ import annotations

import base64
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import hmac
import re
import struct
import threading
import time
from typing import Any, Callable, Iterator
from urllib.parse import urlsplit

try:
    from .mailbox_url_runtime import masked_mailbox_url_row, parse_mailbox_url_row
except ImportError:  # Loaded as a top-level override module by the Mac launcher.
    from mailbox_url_runtime import masked_mailbox_url_row, parse_mailbox_url_row

try:
    from .plain_mailbox_rows import (
        masked_plain_password_row,
        parse_plain_password_mailbox_row,
    )
except ImportError:  # Loaded as a top-level override module by the Mac launcher.
    from plain_mailbox_rows import (
        masked_plain_password_row,
        parse_plain_password_mailbox_row,
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
            f"error={response_error(response) or '-'}",
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
        setattr(transport, "_gptphone_totp_flow", totp_flow)
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
        finally:
            setattr(transport, "_gptphone_totp_flow", False)
            setattr(transport, "_gptphone_totp_secret", "")
            active_state.until = 0.0
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

        replacements = {}
        for line_no, raw in enumerate(raw_lines, start=1):
            parsed_oauth = parse_oauth_mailbox_row(raw)
            parsed_url_totp = parse_mailbox_url_totp_row(raw)
            parsed_totp = parse_chatgpt_totp_row(raw)
            parsed_url = parse_mailbox_url_row(raw)
            parsed_plain = parse_plain_password_mailbox_row(raw)
            if parsed_oauth:
                email, password, oauth_client_id, oauth_refresh_token = parsed_oauth
                entry_key = _entry_key(runtime_module, email, raw)
                replacements[line_no] = runtime_module.PoolEntry(
                    email=email,
                    mailbox_url="",
                    line_no=line_no,
                    key=entry_key,
                    mailbox_type="outlook_oauth",
                    password=password,
                    oauth_client_id=oauth_client_id,
                    oauth_refresh_token=oauth_refresh_token,
                    source_row=f"{email}----***----***----***",
                )
            elif parsed_url_totp:
                email, mailbox_url, totp_secret = parsed_url_totp
                entry_key = _entry_key(runtime_module, email, raw)
                replacements[line_no] = runtime_module.PoolEntry(
                    email=email,
                    mailbox_url=mailbox_url,
                    line_no=line_no,
                    key=entry_key,
                    mailbox_type="url",
                    password="",
                    oauth_client_id="chatgpt_totp",
                    oauth_refresh_token=totp_secret,
                    source_row=masked_mailbox_url_totp_row(raw),
                )
            elif parsed_totp:
                email, password, totp_secret = parsed_totp
                entry_key = _entry_key(runtime_module, email, raw)
                replacements[line_no] = runtime_module.PoolEntry(
                    email=email,
                    mailbox_url="",
                    line_no=line_no,
                    key=entry_key,
                    mailbox_type="outlook_password",
                    password=password,
                    oauth_client_id="chatgpt_totp",
                    oauth_refresh_token=totp_secret,
                    source_row=masked_chatgpt_totp_row(raw),
                )
            elif parsed_url:
                entry_key = _entry_key(runtime_module, parsed_url.email, raw)
                replacements[line_no] = runtime_module.PoolEntry(
                    email=parsed_url.email,
                    mailbox_url=parsed_url.mailbox_url,
                    line_no=line_no,
                    key=entry_key,
                    mailbox_type="url",
                    password="",
                    oauth_client_id="",
                    oauth_refresh_token="",
                    source_row=masked_mailbox_url_row(raw, "***"),
                )
            elif parsed_plain:
                email, password, _delimiter = parsed_plain
                entry_key = _entry_key(runtime_module, email, raw)
                replacements[line_no] = runtime_module.PoolEntry(
                    email=email,
                    mailbox_url="",
                    line_no=line_no,
                    key=entry_key,
                    mailbox_type="outlook_password",
                    password=password,
                    oauth_client_id="",
                    oauth_refresh_token="",
                    source_row=masked_plain_password_row(raw, "***"),
                )
        if not replacements:
            return entries, errors

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
        return patched, errors

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
            code = totp_code(secret)
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


def _entry_key(runtime_module: Any, email: str, raw: str) -> str:
    mailbox_pool = getattr(runtime_module, "_mailbox_pool", None)
    if mailbox_pool is not None:
        return mailbox_pool._entry_key(email, raw.strip())
    return hashlib.sha256(f"{email}\n{raw.strip()}".encode()).hexdigest()
