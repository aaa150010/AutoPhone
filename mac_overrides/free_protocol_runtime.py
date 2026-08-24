"""Full-protocol Free registration driver.

This mixin keeps the recovered OAuth chain and the optional second OTP/2FA
flow separate from task scheduling.  The manager supplies storage, logging,
and stage callbacks through its existing methods.
"""

from __future__ import annotations

import base64
from datetime import datetime
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
from zoneinfo import ZoneInfo

try:
    from .free_mailbox_otp import MailboxUrlOtpProvider, build_free_mailbox_otp_provider
    from .free_protocol_bootstrap import (
        anonymous_warmup as _anonymous_warmup,
        authenticated_warmup as _authenticated_warmup,
        exit_geo_profile as _exit_geo_profile,
        network_preflight as _network_preflight,
    )
    from .free_protocol_flow import run_free_protocol_flow
    from .free_register_common import (
        FIXED_PASSWORD,
        FreeRegisterError,
        FreeTwoFaPending,
        plus_trial_from_accounts as _plus_trial_from_accounts,
        random_birthdate,
        random_display_name,
        safe_log_message as _safe_log_message,
        timezone_offset_minutes as _timezone_offset_minutes,
    )
except ImportError:
    from free_mailbox_otp import MailboxUrlOtpProvider, build_free_mailbox_otp_provider  # type: ignore[no-redef]
    from free_protocol_bootstrap import (  # type: ignore[no-redef]
        anonymous_warmup as _anonymous_warmup,
        authenticated_warmup as _authenticated_warmup,
        exit_geo_profile as _exit_geo_profile,
        network_preflight as _network_preflight,
    )
    from free_protocol_flow import run_free_protocol_flow  # type: ignore[no-redef]
    from free_register_common import (  # type: ignore[no-redef]
        FIXED_PASSWORD, FreeRegisterError, FreeTwoFaPending,
        plus_trial_from_accounts as _plus_trial_from_accounts,
        random_birthdate, random_display_name,
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
REFERENCE_FLOW_PROFILE = "reference_20260823"


def _response_status(response: Any) -> int | None:
    raw = getattr(response, "status_code", None)
    if isinstance(response, Mapping):
        raw = response.get("_status") if "_status" in response else response.get("status_code")
    try:
        return int(raw) if raw is not None else None
    except (TypeError, ValueError):
        return None


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


def _explicit_false(value: Any) -> bool:
    return value is False or (
        isinstance(value, str)
        and value.strip().casefold() in {"false", "0", "no", "failed", "failure", "error"}
    )


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


def _reference_flow_enabled(config: Mapping[str, Any]) -> bool:
    return str(config.get("flow_profile") or REFERENCE_FLOW_PROFILE).strip().lower() != "legacy"


def _reference_fingerprint(config: Mapping[str, Any], task: Mapping[str, Any]) -> dict[str, Any]:
    country = str(task.get("proxy_country") or "US").strip().upper()[:2]
    language = "en-US" if country == "US" else "en-GB"
    return {
        "user_agent": str(config.get("user_agent") or "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/136 Safari/537.36"),
        "navigator_language": language,
        "navigator_languages": [language, "en"],
        "timezone_name": "America/New_York" if country == "US" else "Europe/London",
        "timezone_offset_minutes": -300 if country == "US" else 0,
        "screen_width": 1440,
        "screen_height": 900,
        "hardware_concurrency": 8,
        "device_memory": 8,
        "js_heap_size_limit": 4294705152,
        "country": country,
    }


def _apply_geo_fingerprint(fingerprint: dict[str, Any], geo: Mapping[str, Any]) -> None:
    country = str(geo.get("country") or "").strip().upper()[:2]
    timezone = str(geo.get("timezone") or "").strip()[:100]
    if country:
        language = "en-US" if country == "US" else "en-GB"
        fingerprint.update({
            "country": country,
            "navigator_language": language,
            "navigator_languages": [language, "en"],
        })
    if timezone:
        try:
            offset = datetime.now(ZoneInfo(timezone)).utcoffset()
        except Exception:
            offset = None
        if offset is not None:
            fingerprint.update({
                "timezone_iana": timezone,
                "timezone_name": timezone,
                "timezone_offset_minutes": int(offset.total_seconds() // 60),
            })


def _mark_reference_session_prepared(transport: Any) -> None:
    # Recovered ``initiate_oauth`` creates a new curl session while this flag
    # is false. The reference bootstrap already prepared the task session, so
    # preserving it is required for Cloudflare cookies and anonymous warmup.
    setattr(transport, "chatgpt_signup_done", True)
    setattr(transport, "_gptphone_reference_session_prepared", True)


class FreeProtocolMixin:
    """Protocol driver methods mixed into ``FreeRegisterManager``."""

    _REGISTRATION_COMPLETION_FIELDS = frozenset({
        "registration_completed", "signup_completed", "account_created",
        "account_creation_completed", "oauth_callback_completed",
        "callback_completed", "oauth_code_received", "local_oauth_exchange_ok",
        "local_token_ready", "access_token_present", "token_present", "phase2_ok",
    })

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
        result = dict(raw_result)
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
        token_present = bool(str(result.get("access_token") or result.get("token") or "").strip())
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

    def _run_protocol(self, task: Mapping[str, Any], config: Mapping[str, Any], stop_event: threading.Event, stage: Callable[[str, str], None], log: Callable[[str, str], None], *, twofa_retry: bool = False) -> Mapping[str, Any]:
        # Import the recovered chain inside the worker so fake-runner tests do
        # not need to load the bundled runtime.
        import codex_chain_runner
        import codex_oauth_chain

        task_id = str(task["task_id"])
        email = str(task["email"])
        proxy = str(task["proxy"])
        password = FIXED_PASSWORD
        stage(task_id, "free_twofa_enroll" if twofa_retry else "oauth_create_node")
        resolved_runner = self.resolve_node_runner(config)
        if not resolved_runner:
            raise FreeRegisterError(
                "oauth_create_node", "初始化 Node/Sentinel",
                "SentinelRunner 文件缺失或路径无效，请配置 protocol.node_runner",
                retryable=False, error_code="node_runner_missing",
            )
        def build_oauth_context() -> dict[str, Any]:
            oauth_url, state, code_verifier = codex_chain_runner.build_oauth_url(
                login_hint=email,
                screen_hint="signup",
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
        device_id = str(task.get("device_id") or f"free-{secrets.token_hex(16)}")
        chain_config = dict(config)
        chain_config["codex_node_runner"] = resolved_runner
        chain_config.update({
            "run_mode": "free_register",
            "codex_chain_mode": "real",
            # Free protocol uses the authorize/continue state machine below;
            # the recovered NextAuth + user/register prelude is intentionally
            # disabled because it can retain a stale sign-in session.
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
            log_fn=log, task_id=task_id, stage_fn=stage,
        )

        transport_ref: dict[str, Any] = {}

        def make_transport() -> Any:
            sentinel = make_sentinel()
            created = codex_oauth_chain.RealCodexTransport(
                chain_config, oauth_params=oauth_context["params"], proxy=proxy,
                sentinel_provider=sentinel, device_id=device_id, log_fn=log,
            )
            setattr(created, "_gptphone_free_protocol_state_machine", True)
            if reference_flow:
                setattr(created, "_gptphone_timezone_offset_minutes", fingerprint.get("timezone_offset_minutes"))
            transport_ref["current"] = created
            self._instrument_transport(created, task_id, stage)
            return created

        def prepare_reference_transport(created: Any) -> Any:
            stage(task_id, "free_protocol_preflight")
            preflight = _network_preflight(
                created,
                chain_config,
                log=log,
                stop_requested=stop_event.is_set,
            )
            geo = _exit_geo_profile(created, chain_config, log=log)
            _apply_geo_fingerprint(fingerprint, geo)
            setattr(created, "_gptphone_timezone_offset_minutes", fingerprint.get("timezone_offset_minutes"))
            provider_fingerprint = getattr(getattr(created, "sentinel_provider", None), "fingerprint", None)
            if isinstance(provider_fingerprint, dict) and provider_fingerprint is not fingerprint:
                provider_fingerprint.update(fingerprint)
            warmup = _anonymous_warmup(created, chain_config, log=log)
            _mark_reference_session_prepared(created)
            chain_config["free_protocol_preflight"] = preflight
            chain_config["free_protocol_geo"] = geo
            chain_config["free_protocol_warmup"] = warmup
            log(
                f"[{task_id}/协议画像/free_protocol_fingerprint] 设备、出口画像与预热会话已固定",
                "info",
            )
            return created

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
            if reference_flow and not twofa_retry:
                prepare_reference_transport(transport)
            if twofa_retry:
                saved = self.pool.result(str(task["row_id"]))
                token = str(saved.get("access_token") or "")
                if not token:
                    raise FreeRegisterError("free_twofa_retry", "重试 Free 账号 2FA", "原账号没有可用 access token", retryable=False)
                twofa = self._enroll_twofa(transport, token, task, password, config, otp_provider, stage)
                result = dict(saved)
                for key in ("failure", "error", "error_code", "error_node", "twofa_failure", "twofa_error"):
                    result.pop(key, None)
                result.update(twofa)
                saved_password = str(saved.get("password") or "")
                if saved_password:
                    result["password"] = saved_password
                else:
                    result.pop("password", None)
                if result.get("totp_secret") and saved_password:
                    result["credential_line"] = f"{email}----{result['password']}----{result['totp_secret']}"
                else:
                    result.pop("credential_line", None)
                return result

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
                try:
                    stage(task_id, "free_authenticated_warmup")
                    _authenticated_warmup(transport, chain_config, token, log=log)
                except Exception as exc:
                    # Authenticated warmup is diagnostic and must never turn a
                    # completed registration into a failed account.
                    log(f"[{task_id}/认证预热/free_authenticated_warmup] 跳过：{type(exc).__name__}", "warn")
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
            if bool(config.get("auto_set_2fa", True)):
                try:
                    twofa = self._enroll_twofa(transport, token, task, password, config, otp_provider, stage)
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
            twofa.update({"access_token": token, "has_access_token": True, "account_flow": account_flow, **plan_details})
            if account_flow == "signup":
                twofa["password"] = password
            else:
                twofa.pop("password", None)
            if twofa.get("totp_secret"):
                twofa["twofa_status"] = "enabled"
                if account_flow == "signup":
                    twofa["credential_line"] = f"{email}----{password}----{twofa['totp_secret']}"
                else:
                    twofa.pop("credential_line", None)
            return twofa
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
        headers = {
            "accept": "application/json", "content-type": "application/json",
            "authorization": f"Bearer {token}",
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

        try:
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
                    try:
                        inspect.signature(prepare_mailbox_request).bind("free_twofa_enroll", force_snapshot=True)
                    except ValueError:
                        prepare_mailbox_request("free_twofa_enroll", force_snapshot=True)
                    except TypeError:
                        prepare_mailbox_request("free_twofa_enroll")
                    else:
                        prepare_mailbox_request("free_twofa_enroll", force_snapshot=True)
                phase = (
                    "free_twofa_otp_send", "发送 Free 账号 2FA 邮箱验证码",
                    "free_twofa_otp_send_failed", "保留账号和 Token，检查邮箱重认证状态后重试 2FA",
                )
                sent = send_mfa_otp("")
                sent_status = _response_status(sent)
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
                verified_ok = verified.get("ok") if isinstance(verified, Mapping) else None
                if (verified_status is not None and not 200 <= verified_status < 300) or _explicit_false(verified_ok):
                    fail(f"重新认证 OTP 验证失败（HTTP {verified_status if verified_status is not None else '-'}）", verified)
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
                    str(exc), token=token, plan_type="free", plus_trial_eligible=False,
                    node_code=node_code, node_label=node_label, error_code=error_code,
                    provider_status=exc.provider_status,
                    retryable=bool(exc.retryable),
                    provider_code=str(exc.provider_code or ""),
                    action_hint=str(exc.action_hint or phase[3]),
                ) from exc
            raise FreeTwoFaPending(
                f"2FA 设置失败：{type(exc).__name__}", token=token, plan_type="free", plus_trial_eligible=False,
                node_code=phase[0], node_label=phase[1], error_code=phase[2], retryable=True,
                action_hint=phase[3],
            ) from exc


__all__ = ["FreeProtocolMixin"]
