"""Full-protocol Free registration driver.

This mixin keeps the recovered OAuth chain and the optional second OTP/2FA
flow separate from task scheduling.  The manager supplies storage, logging,
and stage callbacks through its existing methods.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import inspect
import os
from pathlib import Path
import re
import secrets
import threading
import time
from typing import Any, Callable, Mapping
from urllib.parse import parse_qsl, unquote, urlencode, urlsplit, urlunsplit
import uuid

try:
    from .free_failure_runtime import sanitize_safe_page as _sanitize_safe_page
    from .free_mailbox_otp import MailboxUrlOtpProvider, build_free_mailbox_otp_provider
    from .free_protocol_bootstrap import (
        anonymous_warmup as _anonymous_warmup,
        authenticated_warmup as _authenticated_warmup,
        exit_geo_profile as _exit_geo_profile,
        network_preflight as _network_preflight,
        prepare_reference_bootstrap as _prepare_reference_bootstrap,
        prepare_reference_session as _prepare_reference_session,
        _reference_navigation_headers,
    )
    from .free_protocol_flow import run_free_protocol_flow
    from .free_protocol_reference import (
        REFERENCE_FLOW_PROFILE,
        REFERENCE_SENTINEL_VERSION as _REFERENCE_SENTINEL_VERSION,
        REFERENCE_TLS_IMPERSONATE,
        apply_geo_fingerprint as _apply_geo_fingerprint,
        mark_reference_session_prepared as _mark_reference_session_prepared,
        prepare_reference_http_session as _prepare_reference_http_session,
        reference_fingerprint as _reference_fingerprint,
        reference_flow_enabled as _reference_flow_enabled,
    )
    from .free_account_service import (
        finalize_registration_result,
        mfa_enabled_from_payload,
        password_retry_allowed,
    )
    from .free_register_common import (
        FIXED_PASSWORD,
        FreeRegisterError,
        FreeTwoFaPending,
        configured_free_password,
        plus_trial_from_accounts as _plus_trial_from_accounts,
        random_birthdate,
        random_display_name,
        proxy_transport_value,
        safe_log_message as _safe_log_message,
        timezone_offset_minutes as _timezone_offset_minutes,
    )
except ImportError:
    from free_failure_runtime import sanitize_safe_page as _sanitize_safe_page  # type: ignore[no-redef]
    from free_mailbox_otp import MailboxUrlOtpProvider, build_free_mailbox_otp_provider  # type: ignore[no-redef]
    from free_protocol_bootstrap import (  # type: ignore[no-redef]
        anonymous_warmup as _anonymous_warmup,
        authenticated_warmup as _authenticated_warmup,
        exit_geo_profile as _exit_geo_profile,
        network_preflight as _network_preflight,
        prepare_reference_bootstrap as _prepare_reference_bootstrap,
        prepare_reference_session as _prepare_reference_session,
        _reference_navigation_headers,
    )
    from free_protocol_flow import run_free_protocol_flow  # type: ignore[no-redef]
    from free_protocol_reference import (  # type: ignore[no-redef]
        REFERENCE_FLOW_PROFILE,
        REFERENCE_SENTINEL_VERSION as _REFERENCE_SENTINEL_VERSION,
        REFERENCE_TLS_IMPERSONATE,
        apply_geo_fingerprint as _apply_geo_fingerprint,
        mark_reference_session_prepared as _mark_reference_session_prepared,
        prepare_reference_http_session as _prepare_reference_http_session,
        reference_fingerprint as _reference_fingerprint,
        reference_flow_enabled as _reference_flow_enabled,
    )
    from free_account_service import (  # type: ignore[no-redef]
        finalize_registration_result,
        mfa_enabled_from_payload,
        password_retry_allowed,
    )
    from free_register_common import (  # type: ignore[no-redef]
        FIXED_PASSWORD, FreeRegisterError, FreeTwoFaPending, configured_free_password,
        plus_trial_from_accounts as _plus_trial_from_accounts,
        random_birthdate, random_display_name,
        proxy_transport_value,
        safe_log_message as _safe_log_message,
        timezone_offset_minutes as _timezone_offset_minutes,
    )


DEFAULT_AUTH_IMPERSONATES = (
    "chrome",
    "chrome136",
    "chrome133a",
    "safari15_3",
    "safari17_0",
)

# Passwordless signup accounts can opt into a real ChatGPT password after the
# OAuth callback.  This is a different operation from changing an existing
# password: the Auth API uses the ``add_password`` eligibility endpoint and a
# dedicated re-authentication/OTP session (as captured in chatgpt.com.har).
CHATGPT_ADD_PASSWORD_ELIGIBILITY_URL = (
    "https://chatgpt.com/backend-api/accounts/add_password/eligibility"
)


def _response_status(response: Any) -> int | None:
    raw = getattr(response, "status_code", None)
    if isinstance(response, Mapping):
        raw = response.get("_status") if "_status" in response else response.get("status_code")
    try:
        return int(raw) if raw is not None else None
    except (TypeError, ValueError):
        return None


def _response_content_type(response: Any) -> str:
    """Return only the media type from a response-like value."""
    raw: Any = ""
    if isinstance(response, Mapping):
        raw = response.get("_content_type") or response.get("content_type") or ""
        if not raw:
            headers = response.get("headers") or response.get("_headers")
            if isinstance(headers, Mapping):
                raw = headers.get("content-type") or headers.get("Content-Type") or ""
    else:
        headers = getattr(response, "headers", None)
        if isinstance(headers, Mapping):
            raw = headers.get("content-type") or headers.get("Content-Type") or ""
        raw = raw or getattr(response, "content_type", "") or ""
    media_type = str(raw or "").split(";", 1)[0].strip().lower()
    if not re.fullmatch(r"[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+", media_type):
        return ""
    return media_type[:80]


def _response_location_parts(response: Any) -> tuple[str, str]:
    """Extract a response's final host/path without retaining its query."""
    candidates: list[Any] = []
    if isinstance(response, Mapping):
        for key in ("_location", "_url", "location", "url"):
            value = response.get(key)
            if value:
                candidates.append(value)
    else:
        value = getattr(response, "url", "")
        if value:
            candidates.append(value)
    for candidate in candidates:
        try:
            parsed = urlsplit(str(candidate or ""))
            host = str(parsed.hostname or "").strip().lower()
            path = str(parsed.path or "/")
            if host and re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,253}[a-z0-9])?", host):
                # Route paths are useful when diagnosing an auth redirect, but
                # a hostile upstream can put a one-off token/OTP in the path.
                # Reuse the shared page sanitizer so trusted OpenAI routes stay
                # visible while untrusted hosts and sensitive path segments are
                # reduced to a bounded placeholder.  The query/fragment are
                # already excluded by taking ``parsed.path`` above.
                safe_page = _sanitize_safe_page(f"https://{host}{path}")
                if safe_page.startswith(("http://", "https://")):
                    safe_path = str(urlsplit(safe_page).path or "/")
                    safe_segments: list[str] = []
                    for segment in safe_path.split("/"):
                        if not segment:
                            continue
                        decoded = unquote(segment)
                        # Keep ordinary route names, but hide dynamic path
                        # values that commonly carry a token, code or state.
                        # This is a second defense after query removal because
                        # an upstream can place credentials directly in a URL
                        # path (for example ``/callback/<token>``).
                        sensitive_segment = bool(re.search(
                            r"(?i)(?:^|[^a-z0-9])(?:token|secret|password|passwd|code|state|nonce|otp|verifier|key|credential)(?:$|[^a-z0-9])",
                            decoded,
                        ))
                        high_entropy_segment = (
                            len(decoded) >= 20
                            and bool(re.fullmatch(r"[A-Za-z0-9._~-]+", decoded))
                        )
                        if (
                            sensitive_segment
                            or high_entropy_segment
                            or bool(re.fullmatch(r"\d{6,}", decoded))
                            or "@" in decoded
                        ):
                            safe_segments.append("[值已隐藏]")
                        else:
                            cleaned = re.sub(r"[^A-Za-z0-9._~-]", "_", decoded)[:80]
                            safe_segments.append(cleaned or "[值已隐藏]")
                    safe_path = "/" + "/".join(safe_segments)
                else:
                    safe_path = "/[路径已隐藏]"
                return host, safe_path[:240]
        except (TypeError, ValueError):
            continue
    return "", ""


def _emit_twofa_reauth_observation(
    transport: Any,
    task_id: str,
    message: str,
    *,
    response: Any = None,
    request_stage: str = "",
    include_location: bool = False,
    transport_fields: Mapping[str, Any] | None = None,
    outcome: str = "info",
) -> None:
    """Write a credential-free observation for one 2FA re-auth request."""
    logger = getattr(transport, "log_fn", None)
    if not callable(logger):
        return
    # Project optional caller metadata before invoking any logger. The built-in
    # DiagnosticStore applies the same policy again, but third-party callbacks
    # must never receive an unfiltered URL, proxy or credential-bearing field.
    details: dict[str, Any] = {}
    if isinstance(transport_fields, Mapping):
        authorize_url_present = transport_fields.get("authorize_url_present")
        if isinstance(authorize_url_present, bool):
            details["authorize_url_present"] = authorize_url_present
    safe_request_stage = str(request_stage or "").strip().lower()
    if re.fullmatch(r"reauth_[a-z0-9_]{1,48}", safe_request_stage):
        details["request_stage"] = safe_request_stage
    status = _response_status(response)
    content_type = _response_content_type(response)
    if status is not None:
        details.setdefault("http_status", status)
    if content_type:
        details.setdefault("content_type", content_type)
    if include_location:
        host, path = _response_location_parts(response)
        if host:
            details.setdefault("final_host", host)
        if path:
            details.setdefault("final_path", path)
    rendered_parts = [str(message or "").strip()]
    if status is not None and "HTTP " not in rendered_parts[0]:
        rendered_parts.append(f"HTTP {status}")
    if content_type and "Content-Type" not in rendered_parts[0]:
        rendered_parts.append(f"Content-Type {content_type}")
    if include_location:
        host, path = _response_location_parts(response)
        if host and path:
            rendered_parts.append(f"落点 {host}{path}")
    rendered = "；".join(part for part in rendered_parts if part)
    fields: dict[str, Any] = {
        "task_id": task_id,
        "node_code": "free_twofa_reauth",
        "node_label": "Free 2FA 重认证诊断",
        "outcome": outcome,
    }
    if safe_request_stage:
        fields["request_stage"] = safe_request_stage
    if details:
        fields["transport"] = details
    try:
        logger(
            f"[{task_id}/Free 2FA 重认证诊断/free_twofa_reauth] {rendered}",
            "warn" if outcome in {"warn", "skipped"} else "info",
            **fields,
        )
    except TypeError:
        # Older callbacks accept only the historic two positional arguments.
        try:
            logger(
                f"[{task_id}/Free 2FA 重认证诊断/free_twofa_reauth] {rendered}",
                "warn" if outcome in {"warn", "skipped"} else "info",
            )
        except Exception:
            pass
    except Exception:
        pass


def _response_provider_code(response: Any, data: Any = None) -> str:
    for source in (data, response):
        if not isinstance(source, Mapping):
            continue
        error = source.get("error")
        candidates = (error, source) if isinstance(error, Mapping) else (source,)
        for candidate in candidates:
            for key in ("error_code", "code", "type", "reason"):
                value = str(candidate.get(key) or "").strip()
                if value:
                    return _safe_log_message(value)[:120]
    return ""


def _response_continue_url(response: Any) -> str:
    if not isinstance(response, Mapping):
        return ""
    page = response.get("page")
    sources = (page, response) if isinstance(page, Mapping) else (response,)
    for source in sources:
        for key in ("continue_url", "external_url", "redirect_url", "next_url", "location", "url"):
            value = str(source.get(key) or "").strip()
            if value:
                return value
    return ""


def _explicit_false(value: Any) -> bool:
    return value is False or (
        isinstance(value, str)
        and value.strip().casefold() in {"false", "0", "no", "failed", "failure", "error"}
    )


def _config_bool(value: Any, default: bool = False) -> bool:
    """Parse persisted/direct-call booleans without treating ``"false"`` as true."""
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


def _plan_failure(exc: FreeRegisterError) -> dict[str, Any]:
    cause = _safe_log_message(exc) or "服务端未返回错误详情"
    failure = {
        "node_code": "free_plan_check",
        "node_label": "查询 Free 套餐资格",
        "error_code": str(exc.error_code or "free_plan_check_failed"),
        "public_message": f"查询 Free 套餐资格 [查询 Free 套餐资格/free_plan_check]：{cause}",
        "technical_summary": cause,
        "retryable": bool(exc.retryable),
        "action_hint": str(exc.action_hint or "账号已保存；稍后重新测活以补查套餐与试用资格"),
    }
    if exc.provider_status is not None:
        failure["http_status"] = exc.provider_status
    if exc.provider_code:
        failure["provider_code"] = exc.provider_code
    return failure


def _call_otp_wait(provider: Any, email: str, **kwargs: Any) -> str:
    waiter = getattr(provider, "wait_code", None)
    if not callable(waiter):
        raise FreeRegisterError(
            "free_twofa_otp_validate", "等待 Free 账号 2FA 邮箱验证码",
            "邮箱取件 Provider 缺少 wait_code 方法", retryable=False,
            error_code="free_twofa_otp_waiter_missing",
        )
    try:
        inspect.signature(waiter).bind(email, **kwargs)
    except ValueError:
        return waiter(email, **kwargs)
    except TypeError:
        return waiter(email)
    return waiter(email, **kwargs)


def resolve_auth_impersonates(config: Mapping[str, Any]) -> list[str]:
    """Keep explicit candidates; otherwise use the recovered rotation order."""
    for key in ("auth_impersonates", "chatgpt_impersonates"):
        value = config.get(key)
        if isinstance(value, list):
            candidates: list[str] = []
            for item in value:
                name = str(item or "").strip()
                if name and name not in candidates:
                    candidates.append(name)
            if candidates:
                return candidates
    return list(DEFAULT_AUTH_IMPERSONATES)


def _ensure_oauth_context_params(
    oauth_url: str,
    *,
    device_id: str,
    auth_session_logging_id: str,
) -> str:
    """Keep the authorize URL aligned with AutoRegister's browser context."""
    try:
        parsed = urlsplit(str(oauth_url or ""))
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        present = {key for key, _value in pairs}
        additions = (
            ("prompt", "login"),
            ("ext-oai-did", str(device_id or "")),
            ("auth_session_logging_id", str(auth_session_logging_id or "")),
        )
        for key, value in additions:
            if value and key not in present:
                pairs.append((key, value))
                present.add(key)
        return urlunsplit(parsed._replace(query=urlencode(pairs)))
    except (TypeError, ValueError):
        return str(oauth_url or "")


class FreeProtocolMixin:
    """Protocol driver methods mixed into ``FreeRegisterManager``."""

    _REGISTRATION_COMPLETION_FIELDS = frozenset({
        "registration_completed", "signup_completed", "account_created",
        "account_creation_completed", "oauth_callback_completed",
        "callback_completed", "oauth_code_received", "local_oauth_exchange_ok",
        "local_token_ready", "access_token_present", "token_present", "phase2_ok",
    })

    _PROTOCOL_OPTIONAL_TOKEN_KEYS = frozenset({
        "accessToken", "refresh_token", "refreshToken", "id_token", "idToken",
        "token", "session_token", "sessionToken", "expires_at", "expiresAt",
        "token_type", "tokenType", "scope",
    })

    @staticmethod
    def _sanitize_protocol_result(value: Mapping[str, Any] | None) -> dict[str, Any]:
        """Keep only the access token from a protocol account result.

        This gate is deliberately owned by the protocol mixin.  Callers use
        it only when the task driver is ``protocol`` so Camoufox results keep
        their existing token contract.
        """
        result = dict(value) if isinstance(value, Mapping) else {}
        access_token = str(
            result.get("access_token")
            or result.get("accessToken")
            or result.get("token")
            or result.get("session_token")
            or result.get("sessionToken")
            or ""
        ).strip()
        if access_token:
            result["access_token"] = access_token
            result["has_access_token"] = True
        for key in FreeProtocolMixin._PROTOCOL_OPTIONAL_TOKEN_KEYS:
            result.pop(key, None)
        return result

    @staticmethod
    def resolve_node_runner(config: Mapping[str, Any] | None = None) -> str:
        """Resolve the explicit or bundled SentinelRunner without starting it."""
        value = config if isinstance(config, Mapping) else {}
        protocol = value.get("protocol") if isinstance(value.get("protocol"), Mapping) else {}
        node_config = value.get("node") if isinstance(value.get("node"), Mapping) else {}
        app_dir = Path(__file__).resolve().parent.parent
        def existing(candidate: Any) -> str:
            text = str(candidate or "").strip()
            if not text:
                return ""
            path = Path(text).expanduser()
            try:
                if path.is_file() and path.stat().st_size > 0:
                    return str(path.resolve())
            except OSError:
                return ""
            return ""

        # An explicit path is authoritative. Falling back to an unrelated
        # cached runner when this path is stale makes the UI claim a valid
        # configuration while the worker uses a different runtime.
        configured = (
            protocol.get("node_runner") or value.get("codex_node_runner")
            or value.get("node_runner") or node_config.get("runner")
        )
        if str(configured or "").strip():
            return existing(configured)
        environment_runner = os.environ.get("CODEX_NODE_RUNNER")
        if str(environment_runner or "").strip():
            return existing(environment_runner)

        # start.command prepares this stable symlink (or copy) before Flask
        # starts. Keep preflight and the worker on the same path.
        candidates = [
            app_dir / "engine" / "node_chain" / "real_sentinel_runner.js",
            app_dir / "data" / "cache" / "PlusBindTool" / "node_chain" / "real_sentinel_runner.js",
            app_dir / "external_assets" / "real_sentinel_runner.js",
        ]
        data_root = Path(os.environ.get("GPTPHONE_DATA_DIR") or (app_dir / "data")).expanduser()
        for chain_root in (
            data_root / "cache" / "PlusBindTool" / "node_chain",
            app_dir / "data" / "cache" / "PlusBindTool" / "node_chain",
        ):
            if chain_root.is_dir():
                candidates.extend(sorted(chain_root.glob("*/real_sentinel_runner.js"), reverse=True))
        for candidate in candidates:
            resolved = existing(candidate)
            if resolved:
                return resolved
        return ""

    @classmethod
    def protocol_preflight(cls, config: Mapping[str, Any] | None = None) -> dict[str, Any]:
        """Validate Node and SentinelRunner before any mailbox/proxy work starts."""
        runner = cls.resolve_node_runner(config)
        if not runner:
            raise FreeRegisterError(
                "oauth_create_node", "初始化 Node/Sentinel",
                "SentinelRunner 文件缺失或路径无效，请配置 protocol.node_runner",
                retryable=False, error_code="node_runner_missing",
            )
        try:
            from .node_runtime import configure_node_runtime
        except ImportError:
            from node_runtime import configure_node_runtime  # type: ignore[no-redef]
        node = configure_node_runtime()
        if not node:
            raise FreeRegisterError(
                "oauth_create_node", "初始化 Node/Sentinel",
                "未找到可执行的 Node.js，无法启动 SentinelRunner",
                retryable=False, error_code="node_runtime_missing",
            )
        try:
            import codex_node_bridge
            protocol_config = (config or {}).get("protocol") if isinstance((config or {}).get("protocol"), Mapping) else {}
            result = codex_node_bridge.run_node_bridge(
                mode="diagnostic", device_id="free-preflight",
                proxy_label="preflight", proxy="", fingerprint={},
                flow="chat-requirements", persona="chatgpt-noauth",
                script_path=runner, context={"free_preflight": True},
                timeout=max(5, min(60, int(
                    protocol_config.get("sentinel_timeout") or 30
                ))),
            )
        except Exception as exc:
            raise FreeRegisterError(
                "oauth_create_node", "初始化 Node/Sentinel",
                f"SentinelRunner 诊断启动失败（{type(exc).__name__}）",
                retryable=False, error_code="node_sentinel_preflight_failed",
            ) from exc
        if not isinstance(result, Mapping) or not result.get("ok"):
            detail = str(result.get("error") or "未返回诊断详情") if isinstance(result, Mapping) else "未返回有效诊断结果"
            raise FreeRegisterError(
                "oauth_create_node", "初始化 Node/Sentinel",
                f"SentinelRunner 诊断失败：{_safe_log_message(detail)}",
                retryable=False, error_code="node_sentinel_preflight_failed",
            )
        return {"driver": "protocol", "node": str(node), "runner": runner, "sentinel": "available"}

    @staticmethod
    def _protocol_result(raw_result: Any) -> dict[str, Any]:
        """Validate the recovered chain result without changing its node identity."""
        if not isinstance(raw_result, Mapping) or not raw_result:
            raise FreeRegisterError(
                "free_protocol_result", "读取 Free 协议注册结果",
                "协议注册链路未返回结果，未进入 Token 节点",
                error_code="free_protocol_result_empty",
            )
        result = FreeProtocolMixin._sanitize_protocol_result(raw_result)
        ok_marker = result.get("ok")
        explicit_failure = (
            isinstance(ok_marker, bool) and not ok_marker
        ) or (
            isinstance(ok_marker, (int, float)) and not isinstance(ok_marker, bool)
            and ok_marker == 0
        ) or (
            isinstance(ok_marker, str)
            and ok_marker.strip().casefold() in {
                "false", "0", "no", "failed", "failure", "error",
            }
        )
        if explicit_failure:
            detail = _safe_log_message(result.get("error") or "协议注册链路返回失败")
            node_code = str(result.get("node_code") or result.get("stage") or "")
            if not node_code:
                lowered = detail.casefold()
                if any(marker in lowered for marker in ("node_sentinel", "sentinelrunner", "sentinel runner", "node bridge")):
                    node_code = "oauth_create_node"
                elif "callback" in lowered:
                    node_code = "free_oauth_callback"
                elif "otp" in lowered or "verification code" in lowered:
                    node_code = "free_email_otp_validate"
                elif "token" in lowered:
                    node_code = "free_access_token"
                else:
                    node_code = "free_protocol_result"
            node_label = str(result.get("node_label") or "").strip()
            if not node_label:
                node_label = "初始化 Node/Sentinel" if node_code == "oauth_create_node" else "Free 协议注册"
            raise FreeRegisterError(
                node_code, node_label, detail,
                provider_status=result.get("provider_status") or result.get("http_status"),
                error_code=str(result.get("error_code") or f"{node_code}_failed"),
            )
        token_present = bool(str(result.get("access_token") or "").strip())
        if token_present and not FreeProtocolMixin._registration_completion_confirmed(result):
            raise FreeRegisterError(
                "free_protocol_result", "读取 Free 协议注册结果",
                "协议结果包含 Token，但未确认账号创建或 OAuth 回调已完成，已停止继续使用该 Token",
                retryable=False,
                error_code="free_registration_completion_unconfirmed",
            )
        return result

    @classmethod
    def _registration_completion_confirmed(cls, result: Mapping[str, Any]) -> bool:
        """Return whether the recovered chain explicitly reached completion.

        A truthy mapping is not enough: the recovered runtime can return a
        diagnostic/error envelope with ``ok`` set while no account was ever
        created. Token fallback is allowed only after a completion marker or
        an already-present token.
        """
        def marker(value: Any) -> bool:
            if isinstance(value, bool):
                return value
            if isinstance(value, (int, float)):
                return value != 0
            if isinstance(value, str):
                return value.strip().casefold() in {
                    "1", "true", "yes", "y", "ok", "success", "completed", "complete",
                }
            return False

        if any(marker(result.get(field)) for field in cls._REGISTRATION_COMPLETION_FIELDS):
            return True
        status = str(result.get("phase2_status") or result.get("status") or "").strip().lower()
        return status in {"uploaded", "completed", "complete", "success", "succeeded", "ready"}

    @staticmethod
    def _classify_protocol_exception(exc: BaseException) -> FreeRegisterError:
        """Preserve the first recovered protocol node in public task state."""
        detail = _safe_log_message(exc) or type(exc).__name__
        text = detail.lower()
        rules = (
            (("sentinelrunner", "node sentinel", "node_runner", "node bridge"), "oauth_create_node", "初始化 Node/Sentinel", "node_sentinel_failed"),
            (("email otp", "signup_email_otp", "email_verification", "verification code"), "free_email_otp_validate", "验证 Free 邮箱验证码", "free_email_otp_failed"),
            (("register_user", "register failed", "submit email", "email identifier"), "free_email_identifier", "识别 Free 注册邮箱", "free_email_identifier_failed"),
            (("create_account", "account profile", "profile"), "free_account_create", "创建 Free 账号", "free_account_create_failed"),
            (("oauth callback", "oauth_callback", "callback"), "free_oauth_callback", "Free OAuth 回调", "free_oauth_callback_failed"),
            (("access token", "access_token", "token exchange"), "free_access_token", "获取 Free access token", "free_access_token_failed"),
        )
        for needles, node_code, node_label, error_code in rules:
            if any(needle in text for needle in needles):
                return FreeRegisterError(node_code, node_label, detail, error_code=error_code)
        return FreeRegisterError(
            "free_protocol_result", "读取 Free 协议注册结果", detail,
            error_code="free_protocol_result_failed",
        )

    @staticmethod
    def _totp_code(secret: str, now: float | None = None) -> str:
        normalized = re.sub(r"\s+", "", secret or "").upper()
        padding = "=" * ((8 - len(normalized) % 8) % 8)
        key = base64.b32decode(normalized + padding, casefold=True)
        counter = int((now or time.time()) // 30).to_bytes(8, "big")
        digest = hmac.new(key, counter, hashlib.sha1).digest()
        offset = digest[-1] & 15
        value = int.from_bytes(digest[offset:offset + 4], "big") & 0x7fffffff
        return f"{value % 1_000_000:06d}"

    def _run_protocol(
        self,
        task: Mapping[str, Any],
        config: Mapping[str, Any],
        stop_event: threading.Event,
        stage: Callable[[str, str], None],
        log: Callable[[str, str], None],
        *,
        twofa_retry: bool = False,
        password_retry: bool = False,
    ) -> Mapping[str, Any]:
        # Import the recovered chain inside the worker so fake-runner tests do
        # not need to load the bundled runtime.
        import codex_chain_runner
        import codex_oauth_chain

        task_id = str(task["task_id"])
        email = str(task["email"])
        proxy = proxy_transport_value(
            str(task["proxy"]),
            driver="protocol",
            socks5_dns_mode=str(config.get("proxy_socks5_dns_mode") or "remote"),
        )
        if not proxy:
            raise FreeRegisterError(
                "proxy_connect_failed",
                "代理连接失败",
                "协议注册代理格式无效",
                retryable=False,
                error_code="proxy_connect_failed",
            )
        # Resolve the password once from the task's immutable config snapshot.
        # Existing-account login retries still use their saved credential; this
        # value is only for signup/password-continuation requests.
        password = configured_free_password(config)
        stage(
            task_id,
            "free_password_eligibility"
            if password_retry
            else "free_twofa_enroll" if twofa_retry else "oauth_create_node",
        )
        resolved_runner = self.resolve_node_runner(config)
        if not resolved_runner:
            raise FreeRegisterError(
                "oauth_create_node", "初始化 Node/Sentinel",
                "SentinelRunner 文件缺失或路径无效，请配置 protocol.node_runner",
                retryable=False, error_code="node_runner_missing",
            )
        device_id = str(task.get("device_id") or f"free-{secrets.token_hex(16)}")
        auth_session_logging_id = str(uuid.uuid4())

        def build_oauth_context() -> dict[str, Any]:
            # The Windows reference enters a fresh mailbox through its
            # explicit signup authorize branch.  Password/2FA retries are
            # existing-account continuations and must retain the mixed login
            # context so they do not get redirected into signup again.
            screen_hint = "login_or_signup" if (password_retry or twofa_retry) else "signup"
            oauth_url, state, code_verifier = codex_chain_runner.build_oauth_url(
                login_hint=email,
                screen_hint=screen_hint,
                prompt="login",
            )
            oauth_url = _ensure_oauth_context_params(
                oauth_url,
                device_id=device_id,
                auth_session_logging_id=auth_session_logging_id,
            )
            params = codex_oauth_chain.parse_oauth_url(oauth_url)
            return {
                "url": oauth_url,
                "params": params,
                "state": state,
                "code_verifier": code_verifier,
                "client_id": str(params.get("client_id") or ""),
                "redirect_uri": str(params.get("redirect_uri") or ""),
            }

        oauth_context = build_oauth_context()
        chain_config = dict(config)
        chain_config["codex_node_runner"] = resolved_runner
        chain_config.update({
            "run_mode": "free_register",
            "codex_chain_mode": "real",
            # Free protocol owns the post-auth state machine below.  The
            # standalone AutoRegister/NextAuth prelude is deliberately not
            # injected here: it creates a separate CSRF/cookie context and
            # cannot be combined with this task's Codex PKCE state.
            "run_chatgpt_signup_phase": False,
            # Free owns session rebuild and security-page stopping. The
            # recovered transport uses this marker to disable its hidden
            # retry/fingerprint fallback for this workflow only.
            "free_protocol_state_machine": True,
            "free_register_no_phone": True,
            "phone_max_attempts": 1,
            "code_timeout": int(config.get("email_code_timeout") or 90),
            "_stop_requested": stop_event.is_set,
            "_auth_account_email": email,
            "register": {"password": password, "name": random_display_name(), "birthdate": random_birthdate()},
        })
        # The recovered initiate_oauth rotates these candidates only for an
        # OAuth start-page Cloudflare response. Later security pages remain
        # terminal in the Free state machine.
        chain_config["auth_impersonates"] = resolve_auth_impersonates(chain_config)

        reference_flow = _reference_flow_enabled(config)
        chain_config["flow_profile"] = REFERENCE_FLOW_PROFILE if reference_flow else "legacy"
        # The reference profile keeps one anonymous browser/Sentinel image for
        # the whole task. Legacy mode deliberately omits these added fields.
        fingerprint = _reference_fingerprint(config, task) if reference_flow else {}
        if reference_flow:
            protocol_config = dict(chain_config.get("protocol") or {}) if isinstance(chain_config.get("protocol"), Mapping) else {}
            protocol_config.setdefault("sentinel_version", _REFERENCE_SENTINEL_VERSION)
            chain_config["protocol"] = protocol_config
            chain_config["sentinel_version"] = protocol_config["sentinel_version"]
            chain_config["chatgpt_impersonate"] = REFERENCE_TLS_IMPERSONATE
            # Keep the HTTP headers, cookies and Sentinel/browser image on one
            # identity from the first request.  ``prepare_reference_transport``
            # reapplies this after a bounded OAuth session rebuild.
            chain_config["free_protocol_fingerprint"] = dict(fingerprint)

        # The recovered provider reads the runner from the top-level chain
        # configuration. Passing only the nested Free config made a valid
        # runner invisible once the task worker was started.
        def make_sentinel() -> Any:
            """Create request-scoped Sentinel state for each OAuth transport.

            A Sentinel response is tied to the authorization request that
            consumed it. Reusing the provider after an OAuth session rebuild
            can therefore replay an expired token even though the HTTP
            cookies and PKCE context were refreshed.
            """
            sentinel_kwargs: dict[str, Any] = {
                "config": chain_config,
                "device_id": device_id,
                "proxy_label": str(task.get("proxy_fingerprint") or ""),
                "proxy": proxy,
                "log_fn": log,
            }
            if reference_flow:
                sentinel_kwargs["fingerprint"] = fingerprint
            created = codex_oauth_chain.RealNodeSentinelProvider(
                **sentinel_kwargs,
            )
            return created
        otp_provider = build_free_mailbox_otp_provider(
            str(task["mailbox_url"]), proxy, chain_config,
            log_fn=log, task_id=task_id,
            **({"batch_id": str(task.get("batch_id") or "")} if task.get("batch_id") else {}),
            stage_fn=stage,
        )

        transport_ref: dict[str, Any] = {}

        def make_transport() -> Any:
            sentinel = make_sentinel()
            created = codex_oauth_chain.RealCodexTransport(
                chain_config, oauth_params=oauth_context["params"], proxy=proxy,
                sentinel_provider=sentinel, device_id=device_id, log_fn=log,
            )
            # Security-page polling may receive a raw response from the
            # transport session. Bind the recovered parser to this exact
            # transport instead of letting the helper import a process-global
            # parser with an unrelated response contract.
            json_response = getattr(codex_oauth_chain, "_json_response", None)
            if callable(json_response):
                setattr(created, "_gptphone_json_response", json_response)
            # Keep the task-scoped value available for the standalone
            # AutoRegister-compatible prelude module. The Free protocol main
            # flow does not invoke that separate NextAuth session anymore.
            setattr(created, "_gptphone_auth_session_logging_id", auth_session_logging_id)
            setattr(created, "_gptphone_free_protocol_state_machine", True)
            if reference_flow:
                _prepare_reference_http_session(created)
                _prepare_reference_session(created, fingerprint)
                setattr(created, "_gptphone_timezone_offset_minutes", fingerprint.get("timezone_offset_minutes"))
            transport_ref["current"] = created
            self._instrument_transport(created, task_id, stage)
            return created

        def prepare_reference_transport(created: Any) -> Any:
            preflight, geo, warmup = _prepare_reference_bootstrap(
                created,
                fingerprint,
                chain_config,
                task_id=task_id,
                stage=stage,
                stop_requested=stop_event.is_set,
                log=log,
                # Region/IP probing is not part of registration transport and
                # must never gate or consume a Free task. Keep the callback
                # boundary for compatibility but return an empty profile.
                geo_profile=lambda *_args, **_kwargs: {},
                preflight=_network_preflight,
                warmup=_anonymous_warmup,
                apply_geo=lambda _fingerprint, _geo: None,
                mark_prepared=_mark_reference_session_prepared,
            )
            setattr(created, "_gptphone_timezone_offset_minutes", fingerprint.get("timezone_offset_minutes"))
            chain_config["free_protocol_preflight"] = preflight
            chain_config["free_protocol_geo"] = geo
            chain_config["free_protocol_warmup"] = warmup
            chain_config["free_protocol_fingerprint"] = dict(fingerprint)
            # Fingerprint/geo observations are internal transport state. They
            # do not represent an account check and should not create a
            # passive exit-IP validation log entry.
            return created

        def run_authenticated_warmup(created: Any, access_token: str) -> None:
            """Run the reference login bootstrap as a non-blocking diagnostic."""
            try:
                stage(task_id, "free_authenticated_warmup")
                _authenticated_warmup(created, chain_config, access_token, log=log)
            except Exception as exc:
                # Warmup is deliberately best-effort.  A failed warmup must
                # not erase an already valid account or prevent 2FA retry.
                log(
                    f"[{task_id}/认证预热/free_authenticated_warmup] 跳过：{type(exc).__name__}",
                    "warn",
                )

        def make_rebuilt_transport() -> Any:
            created = make_transport()
            if not reference_flow:
                return created
            try:
                return prepare_reference_transport(created)
            except Exception:
                self._close_transport(created)
                raise

        transport = make_transport()
        try:
            if reference_flow:
                # A retry starts from a clean protocol transport. Reapply the
                # same AutoRegister preflight, anonymous cookies and TLS image
                # before the re-authentication flow begins.
                prepare_reference_transport(transport)
            if password_retry:
                saved = self.pool.result(str(task["row_id"]))
                token = str(saved.get("access_token") or "").strip()
                if not token:
                    raise FreeRegisterError(
                        "free_password_retry",
                        "重试 Free 账号密码设置",
                        "原账号没有可用 access token",
                        retryable=False,
                        error_code="free_password_retry_token_missing",
                    )
                if not password_retry_allowed(saved):
                    raise FreeRegisterError(
                        "free_password_retry",
                        "重试 Free 账号密码设置",
                        "该账号当前没有可补设的密码状态",
                        retryable=False,
                        error_code="free_password_retry_not_pending",
                    )
                if reference_flow:
                    run_authenticated_warmup(transport, token)
                result = self._sanitize_protocol_result(saved)
                for key in (
                    "failure", "error", "error_code", "error_node",
                    "password_failure", "password_error",
                ):
                    result.pop(key, None)
                try:
                    password_result = self._set_password(
                        transport, token, task, password, config, otp_provider, stage,
                    )
                except FreeRegisterError as exc:
                    detail = _safe_log_message(exc)
                    result.update({
                        "password_status": "pending",
                        "password_error": detail,
                        "password_failure": {
                            "node_code": exc.node_code,
                            "node_label": exc.node_label,
                            "error_code": exc.error_code,
                            "public_message": (
                                f"{exc.node_label} [{exc.node_label}/{exc.node_code}]：{detail}"
                            ),
                            "technical_summary": detail,
                            "retryable": bool(exc.retryable),
                            "provider_code": str(exc.provider_code or ""),
                        },
                    })
                else:
                    result.update(password_result)
                saved_password = str(result.get("password") or "").strip()
                if saved_password and result.get("totp_secret"):
                    result["credential_line"] = (
                        f"{email}----{saved_password}----{result['totp_secret']}"
                    )
                elif saved_password:
                    result["credential_line"] = f"{email}----{saved_password}"
                return self._sanitize_protocol_result(result)

            if twofa_retry:
                saved = self.pool.result(str(task["row_id"]))
                token = str(saved.get("access_token") or "")
                if not token:
                    raise FreeRegisterError("free_twofa_retry", "重试 Free 账号 2FA", "原账号没有可用 access token", retryable=False)
                if reference_flow:
                    # AutoRegister rehydrates the authenticated ChatGPT
                    # context before starting password re-authentication.
                    # Keep this best-effort and on the same proxy/session.
                    run_authenticated_warmup(transport, token)
                result = self._sanitize_protocol_result(saved)
                for key in ("failure", "error", "error_code", "error_node", "twofa_failure", "twofa_error"):
                    result.pop(key, None)
                saved_password = str(saved.get("password") or "")
                if saved_password:
                    result["password"] = saved_password
                else:
                    result.pop("password", None)
                # A password operation that was pending (or deliberately
                # disabled for a passwordless signup) gets its own retry and
                # OTP baseline before the 2FA retry.
                # Existing-login results are never assigned the fixed signup
                # password implicitly.
                if (
                    _config_bool(config.get("auto_set_password"), False)
                    and password_retry_allowed(saved)
                ):
                    try:
                        password_result = self._set_password(
                            transport, token, task, password, config, otp_provider, stage,
                        )
                    except FreeRegisterError as exc:
                        result.update({
                            "password_status": "pending",
                            "password_error": _safe_log_message(exc),
                            "password_failure": {
                                "node_code": exc.node_code,
                                "node_label": exc.node_label,
                                "error_code": exc.error_code,
                                "public_message": f"{exc.node_label} [{exc.node_label}/{exc.node_code}]：{_safe_log_message(exc)}",
                                "technical_summary": _safe_log_message(exc),
                                "retryable": bool(exc.retryable),
                                "provider_code": str(exc.provider_code or ""),
                            },
                        })
                    else:
                        result.update(password_result)
                        token = str(password_result.get("access_token") or token)
                try:
                    twofa = self._enroll_twofa(transport, token, task, password, config, otp_provider, stage)
                except FreeTwoFaPending as pending:
                    twofa = {
                        "twofa_status": "pending",
                        "twofa_error": _safe_log_message(pending),
                        "twofa_failure": {
                            "node_code": pending.node_code,
                            "node_label": pending.node_label,
                            "error_code": pending.error_code,
                            "public_message": f"{pending.node_label} [{pending.node_label}/{pending.node_code}]：{_safe_log_message(pending)}",
                            "technical_summary": _safe_log_message(pending),
                            "retryable": bool(pending.retryable),
                            "provider_code": str(pending.provider_code or ""),
                        },
                    }
                result.update(twofa)
                saved_password = str(result.get("password") or saved_password or "")
                if saved_password:
                    result["password"] = saved_password
                if result.get("totp_secret") and saved_password:
                    result["credential_line"] = f"{email}----{saved_password}----{result['totp_secret']}"
                elif result.get("password_status") == "enabled" and saved_password:
                    result["credential_line"] = f"{email}----{saved_password}"
                else:
                    result.pop("credential_line", None)
                return self._sanitize_protocol_result(result)

            try:
                raw_result, transport = run_free_protocol_flow(
                    transport,
                    transport_factory=make_rebuilt_transport,
                    oauth_context=dict(oauth_context),
                    email=email,
                    password=password,
                    otp_provider=otp_provider,
                    task_id=task_id,
                    stage=stage,
                    log=log,
                    stop_requested=stop_event.is_set,
                    confirm_mailbox=config.get("_confirm_mailbox_lease")
                    if callable(config.get("_confirm_mailbox_lease")) else None,
                    abort_mailbox_confirmation=config.get(
                        "_abort_mailbox_lease_confirmation"
                    )
                    if callable(config.get("_abort_mailbox_lease_confirmation"))
                    else None,
                )
            except FreeRegisterError:
                raise
            except Exception as exc:
                raise self._classify_protocol_exception(exc) from exc
            result = self._protocol_result(raw_result)
            account_flow = str(result.get("account_flow") or "existing_login")
            token = str(result.get("access_token") or result.get("token") or "")
            if not token:
                raise FreeRegisterError(
                    "free_access_token", "获取 Free access token",
                    "OAuth Token 交换结果未包含 access token",
                    error_code="free_access_token_missing",
                )
            if reference_flow:
                run_authenticated_warmup(transport, token)
            stage(task_id, "free_plan_check")
            try:
                plan_type, eligible = self._plan_check(transport, token)
                plan_details = {
                    "plan_check_status": "success", "plan_type": plan_type,
                    "subscription_plan": plan_type,
                    "has_active_subscription": plan_type not in {"", "free"},
                    "plus_trial_eligible": eligible, "plan_checked_at": time.time(),
                }
            except FreeRegisterError as exc:
                failure = _plan_failure(exc)
                plan_details = {
                    "plan_check_status": "failed",
                    "plan_error_code": failure["error_code"],
                    "plan_http_status": failure.get("http_status"),
                    "plan_failure": failure,
                    "plan_type": "", "plus_trial_eligible": False,
                }
            registration_password_used = bool(result.get("registration_password_used")) if "registration_password_used" in result else (
                account_flow == "signup" and bool(result.get("password"))
            )

            # Passwordless registrations can opt into a password after the
            # account/session callback.  A signup that already traversed the
            # real registration password page is already password-backed and
            # must not trigger a redundant re-authentication OTP.
            if account_flow == "signup" and _config_bool(config.get("auto_set_password"), False) and not registration_password_used:
                try:
                    password_result = self._set_password(
                        transport, token, task, password, config, otp_provider, stage,
                    )
                    token = str(password_result.get("access_token") or token)
                except FreeRegisterError as exc:
                    password_result = {
                        "password_status": "pending",
                        "password_error": _safe_log_message(exc),
                        "password_failure": {
                            "node_code": exc.node_code,
                            "node_label": exc.node_label,
                            "error_code": exc.error_code,
                            "public_message": f"{exc.node_label} [{exc.node_label}/{exc.node_code}]：{_safe_log_message(exc)}",
                            "technical_summary": _safe_log_message(exc),
                            "retryable": bool(exc.retryable),
                            "provider_code": str(exc.provider_code or ""),
                        },
                    }
                result.update(password_result)
            elif registration_password_used and account_flow == "signup":
                result.update({
                    "password_status": "enabled",
                    "password_set_after_registration": False,
                    "password": str(result.get("password") or password),
                })
            else:
                result.setdefault("password_status", "disabled")

            if _config_bool(config.get("auto_set_2fa"), False):
                try:
                    twofa = self._enroll_twofa(transport, token, task, password, config, otp_provider, stage)
                    capture_token = getattr(transport, "chatgpt_access_token", None)
                    if callable(capture_token):
                        refreshed = str(capture_token() or "").strip()
                        if refreshed:
                            token = refreshed
                except FreeTwoFaPending as pending:
                    pending.plan_type = str(plan_details.get("plan_type") or pending.plan_type or "free")
                    pending.plus_trial_eligible = bool(plan_details.get("plus_trial_eligible", pending.plus_trial_eligible))
                    twofa = {"twofa_status": "pending", "twofa_error": _safe_log_message(pending)}
                    twofa["twofa_failure"] = {
                        "node_code": pending.node_code,
                        "node_label": pending.node_label,
                        "error_code": pending.error_code,
                        "public_message": f"{pending.node_label} [{pending.node_label}/{pending.node_code}]：{_safe_log_message(pending)}",
                        "technical_summary": _safe_log_message(pending),
                        "retryable": bool(pending.retryable),
                    }
                    if pending.provider_status is not None:
                        twofa["twofa_failure"]["http_status"] = pending.provider_status
                    if pending.provider_code:
                        twofa["twofa_failure"]["provider_code"] = pending.provider_code
                    if pending.action_hint:
                        twofa["twofa_failure"]["action_hint"] = pending.action_hint
            else:
                twofa = {"twofa_status": "disabled"}
            # Preserve the flow result's password boundary through plan/2FA
            # enrichment.  New flows emit the explicit marker; legacy test
            # doubles only returned ``signup + password``.
            password_set_after_registration = (
                str(result.get("password_status") or "").strip().lower() == "enabled"
                and bool(result.get("password_set_after_registration"))
            )
            twofa.update({
                "access_token": token,
                "has_access_token": True,
                "account_flow": account_flow,
                "registration_password_used": registration_password_used,
                "password_set_after_registration": password_set_after_registration,
                "password_status": str(result.get("password_status") or "disabled"),
                **plan_details,
            })
            for key in ("password", "password_error", "password_failure"):
                if key in result:
                    twofa[key] = result[key]
            if registration_password_used or password_set_after_registration:
                twofa["password"] = str(result.get("password") or password)
            return self._sanitize_protocol_result(finalize_registration_result(
                twofa,
                driver="protocol",
                email=email,
                password_used=registration_password_used or password_set_after_registration,
            ))
        finally:
            try:
                otp_close = getattr(otp_provider, "close", None)
                if callable(otp_close):
                    try:
                        otp_close()
                    except Exception as exc:
                        log(f"邮箱 OTP 客户端清理失败（{type(exc).__name__}），不覆盖原任务结果", "warn")
            finally:
                self._close_transport(transport_ref.get("current") or transport)

    @staticmethod
    def _instrument_transport(transport: Any, task_id: str, stage: Callable[[str, str], None]) -> None:
        mapping = {
            "start_chatgpt_signup_authorize": "free_oauth_session",
            "register_user": "free_email_password",
            "verify_password": "free_email_password",
            "send_passwordless_otp": "free_existing_login_otp",
            "send_mfa_otp": "free_existing_login_otp",
            "verify_signup_email_otp": "free_email_otp_validate",
            "verify_mfa_otp": "free_existing_login_otp",
            "create_account_profile": "free_account_create",
            "complete_chatgpt_callback": "free_oauth_callback",
            "follow_continue_until_code": "free_oauth_callback",
            "exchange_code": "free_access_token",
            "chatgpt_access_token": "free_access_token",
        }
        for name, code in mapping.items():
            original = getattr(transport, name, None)
            if not callable(original):
                continue

            def wrapped(*args: Any, __original: Callable[..., Any] = original, __code: str = code, **kwargs: Any) -> Any:
                stage(task_id, __code)
                return __original(*args, **kwargs)

            setattr(transport, name, wrapped)

    @staticmethod
    def _close_transport(transport: Any) -> None:
        for candidate in (getattr(transport, "session", None), transport):
            close = getattr(candidate, "close", None)
            if callable(close):
                try:
                    close()
                except Exception:
                    pass

    def _plan_check(self, transport: Any, token: str) -> tuple[str, bool]:
        if transport is None:
            raise FreeRegisterError(
                "free_plan_check", "查询 Free 套餐资格", "认证传输会话不可用",
                error_code="free_plan_transport_missing",
                action_hint="账号已保存；重建认证会话后重新测活",
            )
        session = getattr(transport, "session", None)
        if session is None:
            raise FreeRegisterError(
                "free_plan_check", "查询 Free 套餐资格", "认证 HTTP 会话不可用",
                error_code="free_plan_session_missing",
                action_hint="账号已保存；重建认证会话后重新测活",
            )
        try:
            offset = getattr(transport, "_gptphone_timezone_offset_minutes", None)
            if offset is None:
                provider_fingerprint = getattr(getattr(transport, "sentinel_provider", None), "fingerprint", None)
                if isinstance(provider_fingerprint, Mapping):
                    offset = provider_fingerprint.get("timezone_offset_minutes")
            try:
                offset = int(offset) if offset is not None else _timezone_offset_minutes()
            except (TypeError, ValueError):
                offset = _timezone_offset_minutes()
            response = session.get(
                "https://chatgpt.com/backend-api/accounts/check/v4-2023-04-27"
                f"?timezone_offset_min={offset}",
                headers={"authorization": f"Bearer {token}", "accept": "*/*"}, timeout=20,
            )
            status = _response_status(response)
            if status is not None and not 200 <= int(status) < 300:
                data = {}
                try:
                    data = response.json() if hasattr(response, "json") else {}
                except Exception:
                    pass
                raise FreeRegisterError(
                    "free_plan_check", "查询 Free 套餐资格", f"套餐接口返回 HTTP {int(status)}",
                    provider_status=status, provider_code=_response_provider_code(response, data),
                    error_code="free_plan_accounts_http_failed",
                    action_hint="账号已保存；检查认证状态或服务端限流后重新测活",
                )
            data = response.json() if hasattr(response, "json") else {}
            try:
                from .chatgpt_plan_gate import plan_from_accounts_check
            except ImportError:
                from chatgpt_plan_gate import plan_from_accounts_check
            plan, _ = plan_from_accounts_check(data, token=token)
            if not plan:
                raise FreeRegisterError(
                    "free_plan_check", "查询 Free 套餐资格", "套餐接口未返回可识别的套餐",
                    provider_status=status, provider_code=_response_provider_code(response, data),
                    error_code="free_plan_accounts_unrecognized",
                    action_hint="账号已保存；稍后重新测活以刷新套餐信息",
                )
            eligible = _plus_trial_from_accounts(data)
            eligibility = session.get(
                "https://chatgpt.com/backend-api/aip/first-party/eligibility",
                headers={"authorization": f"Bearer {token}", "accept": "application/json"}, timeout=20,
            )
            eligibility_status = _response_status(eligibility)
            if eligibility_status is not None and not 200 <= int(eligibility_status) < 300:
                eligibility_data = {}
                try:
                    eligibility_data = eligibility.json() if hasattr(eligibility, "json") else {}
                except Exception:
                    pass
                raise FreeRegisterError(
                    "free_plan_check", "查询 Free 套餐资格", f"试用资格接口返回 HTTP {int(eligibility_status)}",
                    provider_status=eligibility_status,
                    provider_code=_response_provider_code(eligibility, eligibility_data),
                    error_code="free_plan_eligibility_http_failed",
                    action_hint="账号已保存；稍后重新测活以补查试用资格",
                )
            eligible_data = eligibility.json() if hasattr(eligibility, "json") else {}
            if not isinstance(eligible_data, Mapping):
                raise FreeRegisterError(
                    "free_plan_check", "查询 Free 套餐资格", "试用资格接口响应不是 JSON 对象",
                    provider_status=eligibility_status,
                    error_code="free_plan_eligibility_invalid_json",
                    action_hint="账号已保存；稍后重新测活以补查试用资格",
                )
            eligible = eligible or _plus_trial_from_accounts(eligible_data)
            campaigns = eligible_data.get("eligible_promo_campaigns")
            return plan, bool(eligible or (isinstance(campaigns, Mapping) and campaigns.get("plus")))
        except FreeRegisterError:
            raise
        except Exception as exc:
            raise FreeRegisterError(
                "free_plan_check", "查询 Free 套餐资格",
                f"套餐或试用资格查询异常（{type(exc).__name__}）",
                error_code="free_plan_check_transport_failed",
                diagnostic=f"exception={type(exc).__name__}",
                action_hint="账号已保存；检查认证网络后重新测活",
            ) from exc

    def _set_password(
        self,
        transport: Any,
        token: str,
        task: Mapping[str, Any],
        password: str,
        config: Mapping[str, Any],
        otp_provider: MailboxUrlOtpProvider,
        stage: Callable[[str, str], None],
    ) -> dict[str, Any]:
        """Add a password to a passwordless signup account.

        The Auth API deliberately uses a fresh NextAuth session for this
        operation.  Keep this sequence separate from ``_enroll_twofa`` so a
        password request never probes or otherwise touches ``mfa_info``:

        ``eligibility -> csrf -> signin(openai) -> authorize -> OTP ->
        validate -> password/add -> ChatGPT callback``.

        The method returns a result envelope rather than mutating the task;
        callers can preserve a successfully-created account when a later
        password step is temporarily unavailable.
        """
        task_id = str(task.get("task_id") or "")
        email = str(task.get("email") or "")
        active_token = str(token or "").strip()
        password_value = str(password or configured_free_password(config))
        session = getattr(transport, "session", None)
        if session is None or not callable(getattr(session, "get", None)) or not callable(getattr(session, "post", None)):
            raise FreeRegisterError(
                "free_password_enroll",
                "注册 Free 账号密码",
                "密码设置会话不可用",
                retryable=True,
                error_code="free_password_session_missing",
                action_hint="保留账号和 Token，重建认证会话后重试密码设置",
            )

        phase: list[str] = [
            "free_password_eligibility",
            "检查 Free 账号密码资格",
            "free_password_eligibility_failed",
            "保留账号和 Token，稍后重试密码设置",
        ]

        def response_data(response: Any) -> dict[str, Any]:
            if isinstance(response, Mapping):
                return dict(response)
            try:
                value = response.json() if hasattr(response, "json") else {}
            except Exception:
                value = {}
            return dict(value) if isinstance(value, Mapping) else {}

        def fail(message: str, response: Any = None, data: Any = None) -> None:
            raise FreeRegisterError(
                phase[0],
                phase[1],
                message,
                provider_status=_response_status(response),
                provider_code=_response_provider_code(response, data),
                error_code=phase[2],
                action_hint=phase[3],
            )

        def status_ok(response: Any) -> bool:
            status = _response_status(response)
            return status is None or 200 <= status < 300

        def prepare_mailbox_request() -> None:
            finish = getattr(getattr(otp_provider, "service", None), "state", None)
            finish_request = getattr(finish, "finish_request", None)
            if callable(finish_request) and bool(getattr(finish, "active", False)):
                finish_request()
            prepare = getattr(otp_provider, "prepare", None)
            if not callable(prepare):
                return
            try:
                signature = inspect.signature(prepare)
            except (TypeError, ValueError):
                prepare("free_password_otp_wait", force_snapshot=True)
                return
            for kwargs in (
                {"force_snapshot": True, "notify_stage": False},
                {"force_snapshot": True},
                {},
            ):
                try:
                    signature.bind("free_password_otp_wait", **kwargs)
                except TypeError:
                    continue
                prepare("free_password_otp_wait", **kwargs)
                return
            raise FreeRegisterError(
                "free_password_otp_wait",
                "准备 Free 账号密码邮箱验证码",
                "邮箱 provider 不支持密码验证码准备签名",
                retryable=False,
                error_code="free_password_otp_prepare_failed",
            )

        def auth_headers(referer: str, *, form: bool = False, navigate: bool = False, url: str = "") -> dict[str, str]:
            headers: dict[str, str] = {}
            maker = getattr(transport, "_headers", None)
            if callable(maker):
                try:
                    candidate = maker("password_reauth", referer)
                    if isinstance(candidate, Mapping):
                        headers.update({str(key): str(value) for key, value in candidate.items()})
                except Exception:
                    pass
            if navigate:
                try:
                    headers = _reference_navigation_headers(
                        transport,
                        url or referer,
                        referer,
                        headers,
                    )
                except Exception:
                    headers.setdefault("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
                    headers.setdefault("referer", referer)
                    headers.setdefault("sec-fetch-site", "same-origin")
                    headers.setdefault("sec-fetch-mode", "navigate")
                    headers.setdefault("sec-fetch-dest", "document")
                for key in ("origin", "content-type", "authorization"):
                    headers.pop(key, None)
                return headers
            headers.update({
                "accept": "application/json",
                "origin": "https://chatgpt.com",
                "referer": referer,
            })
            if form:
                headers["content-type"] = "application/x-www-form-urlencoded"
            return headers

        def auth_post(path: str, payload: Mapping[str, Any], *, flow: str, referer: str, timeout: int = 30) -> dict[str, Any]:
            """Call the recovered transport helper, with an old-runtime fallback."""
            helper = getattr(transport, "_post_auth_json", None)
            if callable(helper):
                value = helper(path, dict(payload), flow=flow, referer=referer, timeout=timeout)
                return dict(value) if isinstance(value, Mapping) else {}
            try:
                response = session.post(
                    f"https://auth.openai.com{path}",
                    json=dict(payload),
                    headers=auth_headers(referer),
                    allow_redirects=False,
                    timeout=timeout,
                )
            except Exception as exc:
                return {"_status": 0, "error": type(exc).__name__}
            value = response_data(response)
            status = _response_status(response)
            if status is not None:
                value.setdefault("_status", status)
            return value

        # This endpoint is the only admission check for the post-registration
        # password operation.  An explicit ``eligible: false`` means the
        # account already has a password (or the operation is unavailable), so
        # report it as disabled without attempting a second auth session.
        try:
            eligibility_response = session.get(
                CHATGPT_ADD_PASSWORD_ELIGIBILITY_URL,
                headers={
                    "accept": "application/json",
                    "authorization": f"Bearer {active_token}",
                    "oai-device-id": str(getattr(transport, "device_id", "") or ""),
                },
                timeout=20,
            )
        except Exception as exc:
            fail(f"密码资格请求失败（{type(exc).__name__}）")
        eligibility_data = response_data(eligibility_response)
        eligibility_status = _response_status(eligibility_response)
        if eligibility_status is not None and not 200 <= eligibility_status < 300:
            fail(
                f"密码资格接口返回 HTTP {eligibility_status}",
                eligibility_response,
                eligibility_data,
            )
        if eligibility_data.get("eligible") is False:
            return {
                "password_status": "disabled",
                "password_set_after_registration": False,
            }

        prepare_mailbox_request()
        chatgpt_origin = "https://chatgpt.com"
        auth_origin = "https://auth.openai.com"

        # CSRF and signin are form requests on chatgpt.com.  The
        # ``post_login_add_password`` query flag is what selects the reset
        # password continuation after the OTP, and is intentionally kept out
        # of the ordinary MFA flow.
        phase[:] = [
            "free_password_reauth_csrf",
            "密码设置重认证 CSRF",
            "free_password_reauth_csrf_failed",
            "保留账号和 Token，稍后重试密码设置",
        ]
        try:
            csrf_response = session.get(
                f"{chatgpt_origin}/api/auth/csrf",
                headers=auth_headers(f"{chatgpt_origin}/"),
                timeout=30,
                allow_redirects=True,
            )
            csrf_data = response_data(csrf_response)
        except Exception as exc:
            fail(f"密码设置重认证 CSRF 请求失败（{type(exc).__name__}）")
        csrf_token = str(csrf_data.get("csrfToken") or "")
        if not csrf_token:
            fail(
                f"密码设置重认证 CSRF 响应无效（HTTP {_response_status(csrf_response) or '-'}）",
                csrf_response,
                csrf_data,
            )

        phase[:] = [
            "free_password_reauth_signin",
            "启动密码设置重认证",
            "free_password_reauth_signin_failed",
            "保留账号和 Token，稍后重试密码设置",
        ]
        # Keep this request byte-for-byte compatible with the password-setting
        # HAR: ``connection=password`` belongs to the 2FA re-auth flow, not
        # the add-password continuation.
        signin_query = urlencode({
            "login_hint": email,
            "reauth": "password",
            "post_login_add_password": "true",
            "max_age": "0",
            "ext-oai-did": str(getattr(transport, "device_id", "") or ""),
        })
        signin_body = urlencode({
            "callbackUrl": f"{chatgpt_origin}/",
            "csrfToken": csrf_token,
            "json": "true",
        })
        try:
            signin_response = session.post(
                f"{chatgpt_origin}/api/auth/signin/openai?{signin_query}",
                headers=auth_headers(f"{chatgpt_origin}/", form=True),
                data=signin_body,
                allow_redirects=False,
                timeout=30,
            )
            signin_data = response_data(signin_response)
        except Exception as exc:
            fail(f"密码设置 signin/openai 请求失败（{type(exc).__name__}）")
        auth_url = str(signin_data.get("url") or "").strip()
        if not auth_url:
            fail(
                f"密码设置重认证未返回 authorize 地址（HTTP {_response_status(signin_response) or '-'}）",
                signin_response,
                signin_data,
            )
        try:
            parsed_auth = urlsplit(auth_url)
        except (TypeError, ValueError):
            parsed_auth = None
        if parsed_auth is None or parsed_auth.scheme.casefold() != "https" or (parsed_auth.hostname or "").casefold() != "auth.openai.com":
            fail("密码设置 authorize 地址不是 auth.openai.com", signin_response, signin_data)

        phase[:] = [
            "free_password_reauth_authorize",
            "打开密码设置授权页面",
            "free_password_reauth_authorize_failed",
            "保留账号和 Token，稍后重试密码设置",
        ]
        try:
            authorize_response = session.get(
                auth_url,
                headers=auth_headers(
                    f"{chatgpt_origin}/",
                    navigate=True,
                    url=auth_url,
                ),
                allow_redirects=True,
                timeout=45,
            )
        except Exception as exc:
            fail(f"密码设置 authorize 页面请求失败（{type(exc).__name__}）")
        authorize_status = _response_status(authorize_response)
        if authorize_status is not None and not 200 <= authorize_status < 400:
            fail(
                f"密码设置 authorize 页面返回 HTTP {authorize_status}",
                authorize_response,
                response_data(authorize_response),
            )

        phase[:] = [
            "free_password_otp_wait",
            "等待密码设置邮箱验证码",
            "free_password_otp_wait_failed",
            "保留账号和 Token，确认本次密码设置验证码后重试",
        ]
        mark_sent = getattr(otp_provider, "mark_sent", None)
        if callable(mark_sent):
            mark_sent("free_password_otp_wait")
        code = _call_otp_wait(
            otp_provider,
            email,
            stage_code="free_password_otp_wait",
        )
        if not str(code or "").strip():
            fail("密码设置邮箱验证码为空")

        phase[:] = [
            "free_password_otp_validate",
            "验证密码设置邮箱验证码",
            "free_password_otp_validate_failed",
            "保留账号和 Token，确认验证码属于本次密码设置请求后重试",
        ]
        stage(task_id, "free_password_otp_validate")
        verified = auth_post(
            "/api/accounts/email-otp/validate",
            {"code": str(code).strip()},
            flow="password_add_reauth_email_otp",
            referer=f"{auth_origin}/email-verification",
            timeout=30,
        )
        verified_status = _response_status(verified)
        if (verified_status is not None and not 200 <= verified_status < 300) or _explicit_false(verified.get("ok")):
            fail(
                f"密码设置邮箱验证码验证失败（HTTP {verified_status or '-'}）",
                verified,
                verified,
            )
        reset_url = _response_continue_url(verified)
        if not reset_url:
            fail("密码设置 OTP 响应缺少新密码页面地址", verified, verified)
        try:
            parsed_reset = urlsplit(reset_url)
        except (TypeError, ValueError):
            parsed_reset = None
        if parsed_reset is None or parsed_reset.scheme.casefold() != "https" or (parsed_reset.hostname or "").casefold() != "auth.openai.com" or not parsed_reset.path.startswith("/reset-password/"):
            fail("密码设置 OTP 响应地址不是 auth.openai.com/reset-password 页面", verified, verified)

        # The browser loads the continuation page before submitting the JSON
        # password/add request.  Keep the GET for cookies and server-side
        # continuation state, while never persisting its URL/query.
        phase[:] = [
            "free_password_enroll",
            "打开新密码页面",
            "free_password_enroll_failed",
            "保留账号和 Token，稍后重试密码设置",
        ]
        try:
            reset_response = session.get(
                reset_url,
                headers=auth_headers(
                    f"{auth_origin}/email-verification",
                    navigate=True,
                    url=reset_url,
                ),
                allow_redirects=True,
                timeout=45,
            )
        except Exception as exc:
            fail(f"新密码页面请求失败（{type(exc).__name__}）")
        reset_status = _response_status(reset_response)
        if reset_status is not None and not 200 <= reset_status < 400:
            fail(f"新密码页面返回 HTTP {reset_status}", reset_response, response_data(reset_response))

        phase[:] = [
            "free_password_add",
            "提交 Free 账号密码",
            "free_password_add_failed",
            "保留账号和 Token，稍后重试密码设置",
        ]
        added = auth_post(
            "/api/accounts/password/add",
            {"password": password_value},
            flow="password_add",
            referer=reset_url,
            timeout=30,
        )
        added_status = _response_status(added)
        if (added_status is not None and not 200 <= added_status < 300) or _explicit_false(added.get("ok")):
            fail(
                f"密码添加接口返回 HTTP {added_status or '-'}",
                added,
                added,
            )
        callback_url = _response_continue_url(added)
        if not callback_url:
            fail("密码添加响应缺少 ChatGPT OAuth callback 地址", added, added)
        try:
            parsed_callback = urlsplit(callback_url)
        except (TypeError, ValueError):
            parsed_callback = None
        if parsed_callback is None or parsed_callback.scheme.casefold() != "https" or (parsed_callback.hostname or "").casefold() != "chatgpt.com" or not parsed_callback.path.startswith("/api/auth/callback/"):
            fail("密码添加 callback 地址不是 ChatGPT OAuth callback", added, added)

        phase[:] = [
            "free_password_callback",
            "刷新密码设置会话",
            "free_password_callback_failed",
            "保留账号和 Token，稍后重试密码设置",
        ]
        complete_callback = getattr(transport, "complete_chatgpt_callback", None)
        if callable(complete_callback):
            callback_response = complete_callback(callback_url)
        else:
            try:
                callback_raw = session.get(
                    callback_url,
                    headers=auth_headers(
                        f"{auth_origin}/reset-password/new-password",
                        navigate=True,
                        url=callback_url,
                    ),
                    allow_redirects=True,
                    timeout=45,
                )
            except Exception as exc:
                fail(f"密码设置 OAuth callback 请求失败（{type(exc).__name__}）")
            callback_response = response_data(callback_raw)
            callback_status = _response_status(callback_raw)
            if callback_status is not None and not 200 <= callback_status < 400:
                fail(f"密码设置 OAuth callback 返回 HTTP {callback_status}", callback_raw, callback_response)

        refreshed = ""
        capture_token = getattr(transport, "chatgpt_access_token", None)
        if callable(capture_token):
            try:
                refreshed = str(capture_token() or "").strip()
            except Exception:
                refreshed = ""
        if refreshed:
            active_token = refreshed
        if not active_token:
            fail("密码设置 callback 完成后未取得 ChatGPT Session Token", callback_response, callback_response)
        return {
            "password_status": "enabled",
            "password_set_after_registration": True,
            "password": password_value,
            "access_token": active_token,
            "has_access_token": True,
        }

    def _enroll_twofa(self, transport: Any, token: str, task: Mapping[str, Any], password: str, config: Mapping[str, Any], otp_provider: MailboxUrlOtpProvider, stage: Callable[[str, str], None]) -> dict[str, Any]:
        if transport is None or getattr(transport, "session", None) is None:
            raise FreeTwoFaPending(
                "2FA 会话不可用", token=token, plan_type="free", plus_trial_eligible=False,
                node_code="free_twofa_enroll", node_label="注册 Free 账号 2FA",
                error_code="free_twofa_session_missing",
                action_hint="保留账号和 Token，重建认证会话后重试 2FA",
            )
        session = transport.session
        task_id = str(task["task_id"])
        stage(task_id, "free_twofa_enroll")
        active_token = str(token or "")
        headers = {
            "accept": "application/json", "content-type": "application/json",
            "authorization": f"Bearer {active_token}",
            "oai-device-id": str(getattr(transport, "device_id", "") or ""), "oai-language": "en-GB",
        }
        phase = (
            "free_twofa_enroll", "注册 Free 账号 2FA", "free_twofa_enroll_failed",
            "保留账号和 Token，稍后重试 2FA",
        )

        def fail(message: str, response: Any = None, data: Any = None) -> None:
            raise FreeRegisterError(
                phase[0], phase[1], message,
                provider_status=_response_status(response),
                provider_code=_response_provider_code(response, data),
                error_code=phase[2], action_hint=phase[3],
            )

        def mfa_already_enabled() -> bool:
            """Read the authoritative MFA state for idempotent retries."""
            getter = getattr(session, "get", None)
            if not callable(getter):
                return False
            try:
                response = getter(
                    "https://chatgpt.com/backend-api/accounts/mfa_info",
                    headers=headers,
                    timeout=15,
                )
                status = _response_status(response)
                if status is not None and not 200 <= status < 300:
                    return False
                data = response.json() if hasattr(response, "json") else response
                return bool(mfa_enabled_from_payload(data))
            except Exception:
                # A status-check outage must preserve the original enrollment
                # or activation failure; it is never evidence of success.
                return False

        try:
            post_auth_json = getattr(transport, "_post_auth_json", None)
            if callable(post_auth_json):
                # AutoRegister's setup_2fa starts a fresh NextAuth password
                # re-authentication. The existing-login MFA endpoint is not
                # equivalent and does not produce an MFA-eligible session.
                stage(task_id, "free_twofa_enroll")
                mailbox_service = getattr(otp_provider, "service", None)
                mailbox_state = getattr(mailbox_service, "state", None)
                finish_mailbox_request = getattr(mailbox_state, "finish_request", None)
                if callable(finish_mailbox_request) and bool(getattr(mailbox_state, "active", False)):
                    finish_mailbox_request()
                prepare_mailbox_request = getattr(otp_provider, "prepare", None)
                if callable(prepare_mailbox_request):
                    try:
                        inspect.signature(prepare_mailbox_request).bind("free_twofa_enroll", force_snapshot=True)
                    except ValueError:
                        prepare_mailbox_request("free_twofa_enroll", force_snapshot=True)
                    except TypeError:
                        prepare_mailbox_request("free_twofa_enroll")
                    else:
                        prepare_mailbox_request("free_twofa_enroll", force_snapshot=True)

                session = transport.session
                chatgpt_origin = "https://chatgpt.com"
                auth_origin = "https://auth.openai.com"

                def _reauth_headers(
                    referer: str,
                    *,
                    form: bool = False,
                    navigate: bool = False,
                    url: str = "",
                ) -> dict[str, str]:
                    headers: dict[str, str] = {}
                    maker = getattr(transport, "_headers", None)
                    if callable(maker):
                        try:
                            candidate = maker("twofa_reauth", referer)
                            if isinstance(candidate, Mapping):
                                headers.update({str(k): str(v) for k, v in candidate.items()})
                        except Exception:
                            pass
                    if navigate:
                        # Auth authorize/callback GETs are top-level document
                        # navigations.  Sending the JSON/CORS envelope here
                        # can leave NextAuth in an incomplete re-auth state,
                        # so mirror AutoRegister's browser navigation headers.
                        headers = _reference_navigation_headers(
                            transport,
                            url or referer,
                            referer,
                            headers,
                        )
                        # A document navigation does not carry the API
                        # origin/body headers (and must never forward a Bearer
                        # token to auth.openai.com).
                        for key in ("origin", "content-type", "authorization"):
                            headers.pop(key, None)
                        return headers
                    headers.update({
                        "accept": "application/json",
                        "origin": chatgpt_origin,
                        "referer": referer,
                    })
                    if form:
                        headers["content-type"] = "application/x-www-form-urlencoded"
                    return headers

                csrf_response = None
                csrf_data: Any = {}
                try:
                    csrf_response = session.get(
                        f"{chatgpt_origin}/api/auth/csrf",
                        headers=_reauth_headers(f"{chatgpt_origin}/"),
                        timeout=30,
                        allow_redirects=True,
                    )
                    csrf_data = csrf_response.json() if hasattr(csrf_response, "json") else {}
                except Exception as exc:
                    _emit_twofa_reauth_observation(
                        transport,
                        task_id,
                        f"CSRF 请求异常（{type(exc).__name__}）",
                        request_stage="reauth_csrf",
                        outcome="warn",
                    )
                    fail(f"2FA 重认证 CSRF 请求失败（{type(exc).__name__}）")
                csrf_token = str(csrf_data.get("csrfToken") or "") if isinstance(csrf_data, Mapping) else ""
                csrf_status = _response_status(csrf_response)
                _emit_twofa_reauth_observation(
                    transport,
                    task_id,
                    f"CSRF 响应{'已取得令牌' if csrf_token else '未取得令牌'}",
                    response=csrf_response,
                    request_stage="reauth_csrf",
                )
                if not csrf_token:
                    fail(
                        f"2FA 重认证 CSRF 响应无效（HTTP {csrf_status if csrf_status is not None else '-'}）",
                        csrf_response,
                        csrf_data,
                    )

                signin_query = urlencode({
                    "connection": "password",
                    "login_hint": str(task.get("email") or ""),
                    "reauth": "password",
                    "max_age": "0",
                    "ext-oai-did": str(getattr(transport, "device_id", "") or ""),
                })
                signin_body = urlencode({
                    "callbackUrl": f"{chatgpt_origin}/?action=enable&factor=totp",
                    "csrfToken": csrf_token,
                    "json": "true",
                })
                signin_response = None
                signin_data: Any = {}
                try:
                    signin_response = session.post(
                        f"{chatgpt_origin}/api/auth/signin/openai?{signin_query}",
                        headers=_reauth_headers(f"{chatgpt_origin}/", form=True),
                        data=signin_body,
                        allow_redirects=False,
                        timeout=30,
                    )
                    signin_data = signin_response.json() if hasattr(signin_response, "json") else {}
                except Exception as exc:
                    _emit_twofa_reauth_observation(
                        transport,
                        task_id,
                        f"signin/openai 请求异常（{type(exc).__name__}）",
                        request_stage="reauth_signin",
                        outcome="warn",
                    )
                    fail(f"2FA 重认证启动失败（{type(exc).__name__}）")
                auth_url = str(signin_data.get("url") or "") if isinstance(signin_data, Mapping) else ""
                signin_status = _response_status(signin_response)
                _emit_twofa_reauth_observation(
                    transport,
                    task_id,
                    f"signin/openai 响应，authorize 地址{'已返回' if auth_url else '未返回'}",
                    response=signin_response,
                    request_stage="reauth_signin",
                    transport_fields={"authorize_url_present": bool(auth_url)},
                )
                if not auth_url:
                    fail(
                        f"2FA 重认证启动响应无效（HTTP {signin_status if signin_status is not None else '-'}）",
                        signin_response,
                        signin_data,
                    )
                try:
                    authorize_response = session.get(
                        auth_url,
                        headers=_reauth_headers(
                            f"{chatgpt_origin}/",
                            navigate=True,
                            url=auth_url,
                        ),
                        allow_redirects=True,
                        timeout=45,
                    )
                except Exception as exc:
                    _emit_twofa_reauth_observation(
                        transport,
                        task_id,
                        f"authorize 页面请求异常（{type(exc).__name__}）",
                        request_stage="reauth_authorize",
                        transport_fields={"authorize_url_present": True},
                        outcome="warn",
                    )
                    fail(f"2FA 重认证页面请求失败（{type(exc).__name__}）")
                _emit_twofa_reauth_observation(
                    transport,
                    task_id,
                    "authorize 页面最终响应",
                    response=authorize_response,
                    request_stage="reauth_authorize",
                    include_location=True,
                    transport_fields={"authorize_url_present": True},
                )

                phase = (
                    "free_twofa_otp_send", "发送 Free 账号 2FA 邮箱验证码",
                    "free_twofa_otp_send_failed", "保留账号和 Token，检查邮箱重认证状态后重试 2FA",
                )
                otp_provider.mark_sent("free_twofa_enroll")
                phase = (
                    "free_twofa_otp_validate", "验证 Free 账号 2FA 邮箱验证码",
                    "free_twofa_otp_validate_failed", "保留账号和 Token，确认验证码属于本次 2FA 请求后重试",
                )
                code = _call_otp_wait(
                    otp_provider, str(task.get("email") or ""), stage_code="free_twofa_enroll",
                )
                stage(task_id, "free_email_otp_validate")
                verified = post_auth_json(
                    "/api/accounts/email-otp/validate",
                    {"code": code},
                    flow="twofa_reauth_email_otp",
                    referer=f"{auth_origin}/email-verification",
                    timeout=30,
                )
                verified_status = _response_status(verified)
                _emit_twofa_reauth_observation(
                    transport,
                    task_id,
                    "邮箱 OTP validate 响应",
                    response=verified,
                    request_stage="reauth_otp_validate",
                )
                verified_ok = verified.get("ok") if isinstance(verified, Mapping) else None
                if (verified_status is not None and not 200 <= verified_status < 300) or _explicit_false(verified_ok):
                    fail(f"重新认证 OTP 验证失败（HTTP {verified_status if verified_status is not None else '-'}）", verified)
                continue_url = _response_continue_url(verified)
                if continue_url:
                    try:
                        callback_response = session.get(
                            continue_url,
                            headers=_reauth_headers(
                                f"{auth_origin}/email-verification",
                                navigate=True,
                                url=continue_url,
                            ),
                            allow_redirects=True,
                            timeout=45,
                        )
                    except Exception as exc:
                        _emit_twofa_reauth_observation(
                            transport,
                            task_id,
                            f"OAuth callback 请求异常（{type(exc).__name__}）",
                            request_stage="reauth_callback",
                            outcome="warn",
                        )
                        fail(f"重新认证 OAuth 回调失败（{type(exc).__name__}）")
                    _emit_twofa_reauth_observation(
                        transport,
                        task_id,
                        "OAuth callback 最终响应",
                        response=callback_response,
                        request_stage="reauth_callback",
                        include_location=True,
                    )
                else:
                    fail("重新认证 OTP 响应缺少 OAuth 回调地址", verified)
                capture_token = getattr(transport, "chatgpt_access_token", None)
                if callable(capture_token):
                    refreshed = str(capture_token() or "").strip()
                    if refreshed:
                        active_token = refreshed
                if continue_url and callable(capture_token) and active_token == str(token or "").strip():
                    fail("重新认证 OAuth 回调完成后未提供新的 ChatGPT Session Token")
                headers["authorization"] = f"Bearer {active_token}"
            else:
                # Compatibility for older recovered callers and test doubles.
                send_mfa_otp = getattr(transport, "send_mfa_otp", None)
                verify_mfa_otp = getattr(transport, "verify_mfa_otp", None)
                if callable(send_mfa_otp) and callable(verify_mfa_otp):
                    stage(task_id, "free_twofa_enroll")
                    mailbox_service = getattr(otp_provider, "service", None)
                    mailbox_state = getattr(mailbox_service, "state", None)
                    finish_mailbox_request = getattr(mailbox_state, "finish_request", None)
                    if callable(finish_mailbox_request) and bool(getattr(mailbox_state, "active", False)):
                        finish_mailbox_request()
                    prepare_mailbox_request = getattr(otp_provider, "prepare", None)
                    if callable(prepare_mailbox_request):
                        prepare_mailbox_request("free_twofa_enroll")
                    phase = (
                        "free_twofa_otp_send", "发送 Free 账号 2FA 邮箱验证码",
                        "free_twofa_otp_send_failed", "保留账号和 Token，检查邮箱重认证状态后重试 2FA",
                    )
                    sent = send_mfa_otp("")
                    sent_status = _response_status(sent)
                    _emit_twofa_reauth_observation(
                        transport,
                        task_id,
                        "兼容 2FA OTP 发送响应",
                        response=sent,
                        request_stage="reauth_otp_send",
                    )
                    sent_ok = sent.get("ok") if isinstance(sent, Mapping) else None
                    if (sent_status is not None and not 200 <= sent_status < 300) or _explicit_false(sent_ok):
                        fail(f"重新认证 OTP 发送失败（HTTP {sent_status if sent_status is not None else '-'}）", sent)
                    otp_provider.mark_sent("free_twofa_enroll")
                    phase = (
                        "free_twofa_otp_validate", "验证 Free 账号 2FA 邮箱验证码",
                        "free_twofa_otp_validate_failed", "保留账号和 Token，确认验证码属于本次 2FA 请求后重试",
                    )
                    code = _call_otp_wait(
                        otp_provider, str(task.get("email") or ""), stage_code="free_twofa_enroll",
                    )
                    stage(task_id, "free_email_otp_validate")
                    verified = verify_mfa_otp(code)
                    verified_status = _response_status(verified)
                    _emit_twofa_reauth_observation(
                        transport,
                        task_id,
                        "兼容 2FA OTP validate 响应",
                        response=verified,
                        request_stage="reauth_otp_validate",
                    )
                    verified_ok = verified.get("ok") if isinstance(verified, Mapping) else None
                    if (verified_status is not None and not 200 <= verified_status < 300) or _explicit_false(verified_ok):
                        fail(f"重新认证 OTP 验证失败（HTTP {verified_status if verified_status is not None else '-'}）", verified)
                    continue_url = _response_continue_url(verified)
                    if continue_url:
                        complete_callback = getattr(transport, "complete_chatgpt_callback", None)
                        if not callable(complete_callback):
                            fail("重新认证 OTP 响应包含 OAuth 回调，但传输会话不支持回调", verified)
                        callback = complete_callback(continue_url)
                        callback_status = _response_status(callback)
                        _emit_twofa_reauth_observation(
                            transport,
                            task_id,
                            "兼容 OAuth callback 响应",
                            response=callback,
                            request_stage="reauth_callback",
                            include_location=True,
                        )
                        callback_ok = callback.get("ok") if isinstance(callback, Mapping) else None
                        if (callback_status is not None and not 200 <= callback_status < 300) or _explicit_false(callback_ok):
                            fail(f"重新认证 OAuth 回调失败（HTTP {callback_status if callback_status is not None else '-'}）", callback)
                    capture_token = getattr(transport, "chatgpt_access_token", None)
                    if callable(capture_token):
                        refreshed = str(capture_token() or "").strip()
                        if refreshed:
                            active_token = refreshed
                    headers["authorization"] = f"Bearer {active_token}"
            if mfa_already_enabled():
                return {"twofa_status": "enabled"}
            phase = (
                "free_twofa_enroll", "注册 Free 账号 2FA", "free_twofa_enroll_failed",
                "保留账号和 Token，稍后重试 2FA 注册",
            )
            enrolled = session.post("https://chatgpt.com/backend-api/accounts/mfa/enroll", headers=headers, json={"factor_type": "totp"}, timeout=20)
            enrolled_status = _response_status(enrolled)
            data = enrolled.json() if hasattr(enrolled, "json") else {}
            if enrolled_status is not None and not 200 <= enrolled_status < 300:
                fail(f"2FA enroll 接口返回 HTTP {enrolled_status}", enrolled, data)
            secret = str(data.get("secret") or "")
            session_id = str(data.get("session_id") or "")
            if not secret or not session_id:
                fail("2FA enroll 响应缺少 TOTP 材料", enrolled, data)
            stage(task_id, "free_twofa_activate")
            phase = (
                "free_twofa_activate", "激活 Free 账号 2FA", "free_twofa_activate_failed",
                "保留账号和 Token，稍后重试 2FA 激活",
            )
            activated = session.post(
                "https://chatgpt.com/backend-api/accounts/mfa/user/activate_enrollment",
                headers=headers, json={"code": self._totp_code(secret), "factor_type": "totp", "session_id": session_id}, timeout=20,
            )
            activated_data = activated.json() if hasattr(activated, "json") else {}
            activated_status = _response_status(activated)
            success = activated_data.get("success") if isinstance(activated_data, Mapping) else None
            if (activated_status is not None and not 200 <= activated_status < 300) or success is not True:
                if mfa_already_enabled():
                    # The server may have committed activation while the
                    # response was dropped or reported an idempotent conflict.
                    return {"twofa_status": "enabled", "totp_secret": secret}
                fail(
                    f"2FA 激活失败（HTTP {activated_status if activated_status is not None else '-'}）",
                    activated, activated_data,
                )
            return {"twofa_status": "enabled", "totp_secret": secret}
        except Exception as exc:
            if isinstance(exc, FreeRegisterError):
                node_code = str(exc.node_code or phase[0])
                node_label = str(exc.node_label or phase[1])
                error_code = str(exc.error_code or phase[2])
                if phase[0] in {"free_twofa_otp_send", "free_twofa_otp_validate"} and node_code in {
                    "free_twofa_enroll", "free_email_otp_wait", "free_email_otp_validate",
                    "free_existing_login_otp",
                }:
                    node_code, node_label, error_code = phase[:3]
                raise FreeTwoFaPending(
                    str(exc), token=active_token, plan_type="free", plus_trial_eligible=False,
                    node_code=node_code, node_label=node_label, error_code=error_code,
                    provider_status=exc.provider_status,
                    retryable=bool(exc.retryable),
                    provider_code=str(exc.provider_code or ""),
                    action_hint=str(exc.action_hint or phase[3]),
                ) from exc
            raise FreeTwoFaPending(
                f"2FA 设置失败：{type(exc).__name__}", token=active_token, plan_type="free", plus_trial_eligible=False,
                node_code=phase[0], node_label=phase[1], error_code=phase[2], retryable=True,
                action_hint=phase[3],
            ) from exc


__all__ = ["FreeProtocolMixin"]
