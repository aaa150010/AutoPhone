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
    from .free_autoregister_protocol import run_autoregister_prelude
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
    from .mfa_retry_runtime import mfa_factor_id_from_response
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
    from free_autoregister_protocol import run_autoregister_prelude  # type: ignore[no-redef]
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
    from mfa_retry_runtime import mfa_factor_id_from_response  # type: ignore[no-redef]
    from free_register_common import (  # type: ignore[no-redef]
        FIXED_PASSWORD, FreeRegisterError, FreeTwoFaPending, configured_free_password,
        plus_trial_from_accounts as _plus_trial_from_accounts,
        random_birthdate, random_display_name,
        proxy_transport_value,
        safe_log_message as _safe_log_message,
        timezone_offset_minutes as _timezone_offset_minutes,
    )



# Passwordless signup accounts can opt into a real ChatGPT password after the
# OAuth callback.  This is a different operation from changing an existing
# password: the Auth API uses the ``add_password`` eligibility endpoint and a
# dedicated re-authentication/OTP session (as captured in chatgpt.com.har).


try:
    from .free_protocol_helpers import (
    _response_status,
    _response_content_type,
    _response_location_parts,
    _emit_twofa_reauth_observation,
    _response_provider_code,
    _response_continue_url,
    _explicit_false,
    _config_bool,
    _plan_failure,
    _call_otp_wait,
    resolve_auth_impersonates,
    _ensure_oauth_context_params,
    DEFAULT_AUTH_IMPERSONATES,
    CHATGPT_ADD_PASSWORD_ELIGIBILITY_URL,
    )
    from .free_protocol_password import FreeProtocolPasswordMixin
    from .free_protocol_twofa import FreeProtocolTwoFaMixin
except ImportError:  # macOS launcher imports overrides as top-level modules.
    from free_protocol_password import FreeProtocolPasswordMixin  # type: ignore[no-redef]
    from free_protocol_twofa import FreeProtocolTwoFaMixin  # type: ignore[no-redef]
    from free_protocol_helpers import (  # type: ignore[no-redef]
    _response_status,
    _response_content_type,
    _response_location_parts,
    _emit_twofa_reauth_observation,
    _response_provider_code,
    _response_continue_url,
    _explicit_false,
    _config_bool,
    _plan_failure,
    _call_otp_wait,
    resolve_auth_impersonates,
    _ensure_oauth_context_params,
    DEFAULT_AUTH_IMPERSONATES,
    CHATGPT_ADD_PASSWORD_ELIGIBILITY_URL,
    )


class FreeProtocolMixin(
    FreeProtocolPasswordMixin,
    FreeProtocolTwoFaMixin,
):
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
            # AutoRegister and the Windows browser flow both enter the
            # ChatGPT/NextAuth login_or_signup surface. Keep a PKCE context
            # for compatibility callers, but do not force the direct Codex
            # signup surface for a new mailbox.
            screen_hint = "login_or_signup"
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
            # Free protocol owns the post-auth state machine below. The
            # AutoRegister/NextAuth prelude is injected through the same
            # task-scoped transport and only hands back a recognized page;
            # compatibility callers can still fall back to the PKCE context.
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
        provider_kwargs: dict[str, Any] = {
            "log_fn": log,
            "task_id": task_id,
            "stage_fn": stage,
            **({"batch_id": str(task.get("batch_id") or "")} if task.get("batch_id") else {}),
        }
        if str(task.get("mailbox_source") or "url").strip().lower() == "remail":
            provider_kwargs.update({"mailbox_source": "remail", "mailbox_email": str(task.get("email") or ""), "service_token": str(task.get("service_token") or "")})
        otp_provider = build_free_mailbox_otp_provider(str(task["mailbox_url"]), proxy, chain_config, **provider_kwargs)

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
            # Keep the task-scoped value available for the AutoRegister-
            # compatible prelude, which runs on this exact transport/session.
            setattr(created, "_gptphone_auth_session_logging_id", auth_session_logging_id)
            setattr(created, "_gptphone_free_protocol_state_machine", True)
            if reference_flow:
                _prepare_reference_http_session(created)
                _prepare_reference_session(created, fingerprint)
                setattr(created, "_gptphone_timezone_offset_minutes", fingerprint.get("timezone_offset_minutes"))
            transport_ref["current"] = created
            self._instrument_transport(created, task_id, stage)
            # Per-request timing for the mailbox-identifier submit (the step
            # operators perceive as slow).  Diagnostic only; the wrapper is
            # pure pass-through apart from the elapsed measurement.
            _identifier_original = getattr(created, "submit_email_identifier", None)
            _timing_cb = chain_config.get("_timing_substep") if isinstance(chain_config, Mapping) else None
            if callable(_identifier_original) and callable(_timing_cb) and not getattr(_identifier_original, "_gptphone_timed", False):
                import time as _time

                def _timed_identifier(*args: Any, __original: Callable[..., Any] = _identifier_original, __timing: Callable[..., Any] = _timing_cb, **kwargs: Any) -> Any:
                    _started = _time.monotonic()
                    _outcome = "success"
                    try:
                        return __original(*args, **kwargs)
                    except BaseException:
                        _outcome = "failed"
                        raise
                    finally:
                        try:
                            __timing("free_email_identifier", "email_identifier_submit", int((_time.monotonic() - _started) * 1000), _outcome)
                        except Exception:
                            # Timing telemetry must never alter the identifier submission.
                            pass

                _timed_identifier._gptphone_timed = True
                setattr(created, "submit_email_identifier", _timed_identifier)
            # Same-session transient retry (TLS handshake / connection reset
            # before any response).  Rebuilding the session would drop the
            # oai-did/csrf cookies, so the retry must reuse this session.
            try:
                from .free_protocol_bootstrap import wrap_transport_session_retry
            except ImportError:
                from free_protocol_bootstrap import wrap_transport_session_retry  # type: ignore[no-redef]
            wrap_transport_session_retry(created, log=log)
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

        def run_protocol_prelude(created: Any) -> Mapping[str, Any] | None:
            """Enter the ChatGPT/NextAuth surface on the active transport."""
            return run_autoregister_prelude(
                created,
                email,
                task_id=task_id,
                stage=stage,
                log=log,
                stop_requested=stop_event.is_set,
                config=chain_config,
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
                    if exc.page_type:
                        result["password_failure"]["page_type"] = str(exc.page_type)
                    if exc.safe_page:
                        result["password_failure"]["safe_page"] = str(exc.safe_page)
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
                    prelude=run_protocol_prelude,
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
                    if exc.page_type:
                        password_result["password_failure"]["page_type"] = str(exc.page_type)
                    if exc.safe_page:
                        password_result["password_failure"]["safe_page"] = str(exc.safe_page)
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
                    # Best-effort transport close during session rebuild.
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
                    # A response body is optional detail for the failure raised below.
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
                    # A response body is optional detail for the failure raised below.
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

    @staticmethod
    def _persist_partial(config: Mapping[str, Any], task: Mapping[str, Any], values: Mapping[str, Any], *, stage_code: str) -> bool:
        """Persist mid-flight milestone fields via the manager-injected hook.

        Failures are logged and swallowed: the final result save remains the
        authoritative writer, and a persistence outage must never abort the
        registration flow.
        """
        hook = config.get("_persist_partial_result")
        if not callable(hook):
            return False
        try:
            return bool(hook(dict(values), stage_code=stage_code))
        except Exception:
            # The manager-side hook already logs its own failures; a raising
            # hook must not abort the registration flow either.
            return False

    @staticmethod
    def _confirm_mfa_enabled(transport: Any, session: Any, headers: Mapping[str, str], task_id: str) -> None:
        """Post-activation review (any-auto-register _confirm): re-read
        mfa_info after a successful enroll+activate pair.  Diagnostic only —
        a double-200 activation stands even when the review cannot confirm
        it, so failures are logged and never raised."""
        if not callable(getattr(session, "get", None)):
            return
        logger = getattr(transport, "log_fn", None)

        def _note(message: str) -> None:
            if not callable(logger):
                return
            try:
                logger(message, "warn")
            except TypeError:
                try:
                    logger(message)
                except Exception:
                    # Telemetry must not mask the failure already recorded above.
                    pass
            except Exception:
                # Telemetry must not mask the failure already recorded above.
                pass

        # Bounded confirmation poll instead of a fixed sleep: the activation
        # write is usually visible immediately, so confirm and return at once;
        # a still-pending read gets a short bounded retry window.
        for attempt in range(3):
            if attempt:
                time.sleep(1.0)
            try:
                response = session.get(
                    "https://chatgpt.com/backend-api/accounts/mfa_info",
                    headers=dict(headers),
                    timeout=15,
                )
                status = _response_status(response)
                if status is not None and 200 <= status < 300:
                    data = response.json() if hasattr(response, "json") else {}
                    if mfa_enabled_from_payload(data):
                        return
                if attempt == 2:
                    _note(f"[{task_id}/free_twofa_activate] 2FA 激活复核未确认 mfa_enabled（HTTP {status if status is not None else '-'}），激活响应已按成功处理")
            except Exception as exc:
                if attempt == 2:
                    _note(f"[{task_id}/free_twofa_activate] 2FA 激活复核异常（{type(exc).__name__}），激活响应已按成功处理")




__all__ = ["FreeProtocolMixin"]
