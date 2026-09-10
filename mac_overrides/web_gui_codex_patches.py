"""Codex transport patches for the recovered web GUI, hosted by web_gui.

Every patched callable receives the hosting ``web_gui`` module as its first
``host`` argument so late-bound module globals (including test rebindings of
``_ORIGINAL_*`` names and runtime singletons) keep their original semantics.
"""

from __future__ import annotations

import requests

# Bound by web_gui at import time; the ReloginPhoneOtpProvider static methods
# keep their recovered signatures so the recovered transport can call them.
_host = None


def bind_host(module):
    global _host
    _host = module



def real_transport_init(host, 
    self,
    config,
    *,
    oauth_params,
    proxy="",
    sentinel_provider,
    device_id="",
    log_fn=None,
):
    host._ORIGINAL_REAL_TRANSPORT_INIT(
        self,
        config,
        oauth_params=oauth_params,
        proxy=proxy,
        sentinel_provider=sentinel_provider,
        device_id=device_id,
        log_fn=log_fn,
    )
    runtime_config = config if isinstance(config, dict) else {}
    self.account_email = str(runtime_config.get("_auth_account_email") or "").strip().lower()
    self._gptphone_totp_refresh_in_headers = True
    self._gptphone_totp_manual_secret = ""
    self._gptphone_mfa_fresh_retry_generation = None
    self._gptphone_mfa_fresh_retry_markers = set()
    self._gptphone_checkpoint_restored = False
    host._auth_request_runtime_ext.ensure_transport_context(self, host._AUTH_SESSIONS, force_new=True)
    # The recovered transport creates curl_cffi sessions with certificate
    # verification disabled.  Free must not inherit that unsafe default; set
    # the session policy after construction without touching the recovered
    # runtime artifact.
    session = getattr(self, "session", None)
    if runtime_config.get("free_protocol_state_machine") and session is not None and hasattr(session, "verify"):
        try:
            session.verify = True
        except Exception as exc:
            # Session hardening is best-effort; keep the transport usable.
            _note_stderr("session_verify_sm", exc)
    # Free's protocol state machine owns a fresh OAuth session and its single
    # controlled rebuild. Restoring a recovered Phase1 checkpoint here would
    # reintroduce ordinary SMS cookies/CSRF and make a supposedly new Free
    # authorization depend on another workflow's persisted state.
    is_free_protocol = bool(runtime_config.get("free_protocol_state_machine"))
    if host._RUN_MODE_CONTEXT.get() != "relogin" and not is_free_protocol:
        # Keep bounded checkpoint recovery visible as its own OAuth node.
        host._set_current_task_stage("oauth_session")
        restored = host._PHASE1_CHECKPOINTS_COORDINATOR.restore(self)
        if not restored:
            host._set_current_task_stage("oauth_create_node")
    elif is_free_protocol:
        host._set_current_task_stage("oauth_create_node")
    host._register_sms_transport(host._transport_task_id(self), self)
    host._ACTIVE_SMS_TRANSPORT.set(self)


def is_free_transport(host, self) -> bool:
    """Return whether a recovered transport belongs to a Free workflow.

    The recovered transport is shared by ordinary SMS/OAuth and Free.  Keep
    the stricter TLS/environment policy scoped to Free so ordinary behavior is
    not changed accidentally.
    """
    config = getattr(self, "config", None)
    if not isinstance(config, dict):
        return False
    if config.get("free_protocol_state_machine") or config.get("free_register_no_phone"):
        return True
    return str(config.get("run_mode") or "").strip().lower().startswith("free_")


def real_new_session(host, self, impersonate="chrome"):
    """Create a Free session with explicit TLS and proxy semantics.

    ``RealCodexTransport.initiate_oauth`` calls this method again when it
    rotates an impersonation or rebuilds an expired OAuth session.  The
    recovered implementation hard-codes ``verify=False`` and leaves
    ``trust_env`` enabled, which silently reintroduces the unsafe policy after
    ``__init__`` has applied its one-time fix.  Ordinary transports continue
    through the captured implementation unchanged.
    """
    if not is_free_transport(host, self):
        return host._ORIGINAL_REAL_NEW_SESSION(self, impersonate)

    session = None
    curl_requests = getattr(self, "_curl_requests", None)
    if bool(getattr(self, "_curl", False)) and curl_requests is not None:
        try:
            session = curl_requests.Session(
                impersonate=str(impersonate or "chrome"),
                verify=True,
                trust_env=False,
            )
        except TypeError:
            # A small number of curl_cffi-compatible test doubles do not
            # accept constructor keyword arguments; enforce the same policy
            # after creating the object.
            try:
                session = curl_requests.Session(impersonate=str(impersonate or "chrome"))
            except TypeError:
                session = curl_requests.Session()
    else:
        import requests

        session = requests.Session()

    try:
        session.verify = True
    except Exception as exc:
        # Session hardening is best-effort; keep the transport usable.
        _note_stderr("session_verify", exc)
    try:
        session.trust_env = False
    except Exception as exc:
        # Session hardening is best-effort; keep the transport usable.
        _note_stderr("session_trust_env", exc)

    # The registration proxy is explicit and remains fixed for this task.
    # Never merge values from the process environment into a Free session.
    proxy = str(getattr(self, "proxy", "") or "").strip()
    if proxy:
        try:
            session.proxies = {"http": proxy, "https": proxy}
        except Exception as exc:
            # Proxy pinning is best-effort; keep the transport usable.
            _note_stderr("proxy_pinning", exc)
    return session




def real_headers(host, self, flow, referer):
    headers = host._ORIGINAL_REAL_HEADERS(self, flow, referer)
    host._chatgpt_totp_ext.refresh_transport_totp_payload(self, flow)
    return host._auth_request_runtime_ext.request_headers(self, headers)


def observe_protocol_request_activity(host):
    host._PROTOCOL_REQUEST_ACTIVITY.set(host._PROTOCOL_REQUEST_ACTIVITY.get() + 1)


def real_post_auth_json(host, self, path, payload, *, flow, referer, timeout=30):
    stage = {
        "/api/accounts/email-otp/validate": "email_code_verifying",
        "/api/accounts/mfa/verify": "mfa_otp_verifying",
        "/api/accounts/phone-otp/validate": "sms_verifying",
    }.get(str(path), "oauth_authorize_node")
    host._set_current_task_stage(stage)
    request_context = host._auth_request_runtime_ext.begin_request(
        self,
        host._AUTH_SESSIONS,
        endpoint=path,
        stage=stage,
    )
    try:
        response = host._with_transport_protocol_lease(
            self,
            lambda: host._ORIGINAL_REAL_POST_AUTH_JSON(
                self,
                path,
                payload,
                flow=flow,
                referer=referer,
                timeout=timeout,
            ),
        )
    except Exception as exc:
        if host._auth_session_runtime_ext.is_session_invalid(exc):
            host._checkpoint_delete_after_auth(self)
            host._auth_request_runtime_ext.invalidate_auth_session(
                self,
                host._AUTH_SESSIONS,
                exc,
                stage=str(request_context.get("stage") or "oauth_authorize_node"),
            )
        raise
    def _fresh_mfa_post_json(transport, fresh_path, fresh_payload, **kwargs):
        """Keep one-time MFA recovery inside the staged protocol gate."""
        return host._with_transport_protocol_lease(
            transport,
            lambda: host._ORIGINAL_REAL_POST_AUTH_JSON(
                transport,
                fresh_path,
                fresh_payload,
                **kwargs,
            ),
        )

    if getattr(self, "_gptphone_free_protocol_state_machine", False):
        # Free's protocol state machine owns MFA phase boundaries and allows
        # only its own bounded resend/rebuild policy.  The ordinary SMS
        # recovery helper may issue a hidden challenge refresh here, which can
        # consume a second OTP before Free has recorded its baseline.
        _mfa_retry_attempted = False
    else:
        response, _mfa_retry_attempted = host._mfa_retry_runtime_ext.retry_expired_mfa_step(
            self,
            path=path,
            payload=payload,
            response=response,
            generation=request_context.get("session_generation"),
            post_json=_fresh_mfa_post_json,
            pending_totp_payload=host._chatgpt_totp_ext.pending_transport_totp_payload,
            success_fn=host._codex_oauth_chain._is_success_response,
            auth_origin=host._codex_oauth_chain.AUTH,
            timeout=timeout,
            log_fn=getattr(self, "log_fn", None),
        )
    finished = host._auth_request_runtime_ext.finish_request(
        self,
        host._AUTH_SESSIONS,
        request_context,
        response,
    )
    self._gptphone_last_request_context = finished
    if host._auth_session_runtime_ext.is_session_invalid(response):
        host._checkpoint_delete_after_auth(self)
        host._auth_request_runtime_ext.invalidate_auth_session(
            self,
            host._AUTH_SESSIONS,
            response,
            stage=str(request_context.get("stage") or "oauth_authorize_node"),
        )
    return response


def real_post_auth_json_without_sentinel(host, self, path, payload, *, flow, referer, timeout=30):
    """POST an Auth JSON envelope without generating a Sentinel token.

    Auth's password-add reauthentication accepts the email OTP validation as
    a same-origin JSON request without Sentinel (the HAR/AutoRegister path).
    Keep this as a separate transport method so the recovered generic helper,
    and therefore ordinary registration/MFA behavior, remains unchanged.
    """
    stage = {
        "/api/accounts/email-otp/validate": "email_code_verifying",
        "/api/accounts/mfa/verify": "mfa_otp_verifying",
        "/api/accounts/phone-otp/validate": "sms_verifying",
    }.get(str(path), "oauth_authorize_node")
    host._set_current_task_stage(stage)
    request_context = host._auth_request_runtime_ext.begin_request(
        self,
        host._AUTH_SESSIONS,
        endpoint=path,
        stage=stage,
    )

    def request():
        # Match RealCodexTransport._headers()' browser envelope, but do not
        # call it: that recovered method unconditionally asks SentinelRunner
        # for a token.  request_headers() still adds the per-request flow
        # invocation id and explicitly strips any accidental Sentinel fields.
        headers = dict(getattr(host._codex_oauth_chain, "JSON_HEADERS", {}) or {})
        headers.update({
            "referer": str(referer or ""),
            "oai-device-id": str(getattr(self, "device_id", "") or ""),
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-origin",
        })
        headers = host._auth_request_runtime_ext.request_headers(
            self,
            headers,
            include_sentinel=False,
        )
        try:
            response = self.session.post(
                f"{host._codex_oauth_chain.AUTH}{path}",
                json=payload,
                headers=headers,
                allow_redirects=False,
                timeout=timeout,
            )
            parser = getattr(self, "_gptphone_json_response", None)
            if not callable(parser):
                parser = getattr(host._codex_oauth_chain, "_json_response", None)
            data = parser(response) if callable(parser) else {}
            return data if isinstance(data, dict) else {}
        except Exception as exc:
            return {
                "_status": 0,
                "_content_type": "",
                "_body": str(exc)[:220],
                "_body_summary": str(exc)[:220],
                "_location": "",
                "error": str(exc)[:220],
            }

    response = host._with_transport_protocol_lease(self, request)
    finished = host._auth_request_runtime_ext.finish_request(
        self,
        host._AUTH_SESSIONS,
        request_context,
        response,
    )
    self._gptphone_last_request_context = finished
    if host._auth_session_runtime_ext.is_session_invalid(response):
        host._checkpoint_delete_after_auth(self)
        host._auth_request_runtime_ext.invalidate_auth_session(
            self,
            host._AUTH_SESSIONS,
            response,
            stage=str(request_context.get("stage") or "oauth_authorize_node"),
        )
    return response


def observe_auth_step(host, transport, response, stage):
    host._auth_request_runtime_ext.observe_auth_response(
        transport,
        host._AUTH_SESSIONS,
        response,
        stage=stage,
    )
    page_type = host._codex_oauth_chain._page_type(response)
    if host._auth_request_runtime_ext.is_phone_page_type(page_type):
        provider = getattr(transport, "sentinel_provider", None)
        reset = getattr(provider, "reset", None)
        if callable(reset):
            reset()
        host._auth_request_runtime_ext.mark_phone_ready(
            transport,
            host._AUTH_SESSIONS,
            response,
            continue_url=host._codex_oauth_chain._continue_url(response),
        )


def real_submit_email_identifier(host, self, email):
    if getattr(self, "_gptphone_free_protocol_state_machine", False):
        # The recovered method retries an invalid authorize session internally
        # and may switch fingerprint after a challenge. Free's state machine
        # owns those policies, so perform exactly one POST here and let the
        # caller classify/rebuild it.
        response = host._with_transport_protocol_lease(
            self,
            lambda: host._ORIGINAL_REAL_POST_AUTH_JSON(
                self,
                "/api/accounts/authorize/continue",
                {"username": {"kind": "email", "value": email}},
                flow="authorize_continue",
                referer="https://auth.openai.com/log-in",
                timeout=30,
            ),
        )
    else:
        response = host._ORIGINAL_REAL_SUBMIT_EMAIL_IDENTIFIER(self, email)
    observe_auth_step(host, self, response, "email_identifier")
    if not host._codex_oauth_chain._is_success_response(response) or not host._free_protocol_diagnostics_ext.is_email_otp_response(
        host._codex_oauth_chain._page_type(response),
        host._codex_oauth_chain._continue_url(response),
        normalize_page_type=host._auth_request_runtime_ext.normalize_page_type,
    ):
        if getattr(self, "_gptphone_free_protocol_state_machine", False):
            return response
        return host._auth_challenge_runtime_ext.continue_if_needed(
            self, response, origin="submit_email"
        )

    # The successful browser trace explicitly resends after reaching the OTP
    # page. Merely receiving that page does not prove that an email was sent.
    host._set_current_task_stage("email_code_waiting")
    continue_url = host._codex_oauth_chain._continue_url(response)
    send_response = self.send_email_otp(continue_url)
    if not host._codex_oauth_chain._is_success_response(send_response):
        cause = host._codex_oauth_chain._error_text(send_response) or "发送接口未返回错误详情"
        failure = host._error_observability_ext.classify_failure(
            result=send_response,
            error=cause,
            progress={"code": "email_code_waiting"},
            status="retryable_infra",
        )
        qualifiers = []
        status = host._safe_response_status(send_response)
        if status is not None:
            qualifiers.append(f"HTTP {status}")
        provider_code = str(failure.get("provider_code") or "").strip().lower()
        if provider_code:
            qualifiers.append(provider_code)
        prefix = f"{' / '.join(dict.fromkeys(qualifiers))}: " if qualifiers else ""
        raise _host._codex_oauth_chain.CodexChainError(
            f"email_otp_send_failed: {prefix}{cause}"
        )
    self._gptphone_initial_email_otp_send_confirmed = True
    host._call_log(
        getattr(self, "log_fn", None),
        "  [邮箱验证码发送/email_code_waiting] 首次邮箱验证码发送接口已确认",
        "info",
    )
    if getattr(self, "_gptphone_free_protocol_state_machine", False):
        return response
    return host._auth_challenge_runtime_ext.continue_if_needed(
        self, response, origin="submit_email"
    )


def real_verify_password(host, self, password):
    response = host._TOTP_PATCHES.verify_password(self, password)
    observe_auth_step(host, self, response, "email_password")
    if getattr(self, "_gptphone_free_protocol_state_machine", False):
        return response
    return host._auth_challenge_runtime_ext.continue_if_needed(
        self, response, origin="password"
    )


def manual_totp_fallback(host, self, response):
    error_code = host._mfa_retry_runtime_ext.response_error_code(response)
    secret = str(getattr(self, "_gptphone_totp_manual_secret", "") or "").strip()
    task_id = host._transport_task_id(self) or host._TASK_CONTEXT.get()
    manual_generation = host._manual_task_generation(task_id) if task_id else -1
    manual_attempted = (
        getattr(self, "_gptphone_totp_manual_retry_generation", None)
        == manual_generation
    )
    setattr(self, "_gptphone_totp_manual_fallback_consumed", manual_attempted)
    session_invalid = host._auth_session_runtime_ext.is_session_invalid(response)
    if session_invalid:
        try:
            delattr(self, "_gptphone_totp_manual_secret")
        except AttributeError:
            pass
    if error_code == "incorrect_code" and secret and task_id and not session_invalid:
        setattr(self, "_gptphone_totp_manual_fallback_consumed", True)
        try:
            delattr(self, "_gptphone_totp_manual_secret")
        except AttributeError:
            pass
        host._call_log(
            getattr(self, "log_fn", None),
            "  [2FA/mfa_otp_verifying] 动态码自动验证失败，不打开人工输入",
            "warn",
        )
    elif error_code == "incorrect_code" and manual_attempted:
        try:
            delattr(self, "_gptphone_totp_manual_secret")
        except AttributeError:
            pass
    return response


def real_verify_mfa_otp(host, self, code):
    response = manual_totp_fallback(host, self, host._TOTP_PATCHES.verify_mfa_otp(self, code))
    host._checkpoint_save_after_auth(self, response)
    observe_auth_step(host, self, response, "mfa_otp_verifying")
    if (
        getattr(self, "_gptphone_totp_manual_fallback_consumed", False)
        and host._mfa_retry_runtime_ext.response_error_code(response) == "incorrect_code"
    ):
        return response
    if getattr(self, "_gptphone_free_protocol_state_machine", False):
        return response
    return host._auth_challenge_runtime_ext.continue_if_needed(
        self, response, origin="mfa"
    )


def real_send_mfa_otp(host, self, continue_url=""):
    host._set_current_task_stage("mfa_otp_verifying")
    return host._with_transport_protocol_lease(
        self,
        lambda: host._TOTP_PATCHES.send_mfa_otp(self, continue_url),
    )


class ReloginPhoneOtpProvider:
    """Hard stop for relogin tasks before any SMS provider can be called."""

    @staticmethod
    def get_number(**_kwargs):
        _host._set_current_task_stage("phone_acquiring")
        raise _host._codex_oauth_chain.CodexChainError(
            "relogin_phone_required: 重登进入手机号验证页面，已停止且未调用接码平台"
        )

    @staticmethod
    def mark_ready(_lease):
        return None

    @staticmethod
    def wait_code(_lease, timeout=180):
        del timeout
        raise _host._codex_oauth_chain.CodexChainError(
            "relogin_phone_required: 重登禁止等待短信验证码"
        )

    @staticmethod
    def complete(_lease):
        return None

    @staticmethod
    def cancel(_lease, reason=""):
        del reason
        return None


def run_codex_after_registration(
    host,
    *,
    oauth_url,
    code_verifier="",
    account_email="",
    password="",
    phase1_register=None,
    phase1_response=None,
    phase1_continue_url="",
    sms_provider=None,
    config=None,
    proxy="",
    email_proxy="",
    upload_proxy="",
    log_fn=None,
    mode="",
    local_oauth_client_id="app_EMoamEEZ73f0CkXaXp7hrann",
    local_oauth_redirect_uri="http://localhost:1455/auth/callback",
    oauth_provider="",
    oauth_session_id="",
    oauth_state="",
    upload_target_name="local",
    node_result=None,
    runtime_context_expected=None,
    runtime_context_strict=False,
    transport=None,
    sentinel_provider=None,
    email_otp_provider=None,
    phone_otp_provider=None,
):
    runtime_config = config if isinstance(config, dict) else {}
    task_id_hint = host._oauth_mfa_runtime_ext.runtime_task_id(
        runtime_config,
        context_task_get=host._TASK_CONTEXT.get,
        transport=transport,
        transport_task_id_get=host._transport_task_id,
    )
    bound_totp_task_id = ""
    try:
        bound_totp_task_id = host._oauth_mfa_runtime_ext.bind_provider_totp_secret(
            email_otp_provider,
            host._TASK_TOTP_SECRETS,
            task_id=task_id_hint,
            current_task_get=host._TASK_CONTEXT.get,
        )
        if str(runtime_config.get("run_mode") or "").strip().lower() == "relogin":
            phone_otp_provider = ReloginPhoneOtpProvider()
        runtime_config["_auth_account_email"] = str(account_email or "").strip().lower()
        if transport is not None:
            transport.config = runtime_config
            transport.account_email = runtime_config["_auth_account_email"]
            host._auth_challenge_runtime_ext.bind_transport_context(
                transport,
                account_email=account_email,
                password=password,
                email_otp_provider=email_otp_provider,
                config=runtime_config,
                log_fn=log_fn,
                page_type_fn=host._codex_oauth_chain._page_type,
                continue_url_fn=host._codex_oauth_chain._continue_url,
                success_fn=host._codex_oauth_chain._is_success_response,
            )
            existing_context = getattr(transport, "_gptphone_request_context", None)
            expected_task_id = task_id_hint
            request_context = host._auth_request_runtime_ext.ensure_transport_context(
                transport,
                host._AUTH_SESSIONS,
                force_new=bool(
                    existing_context is None
                    or getattr(existing_context, "task_id", "") != expected_task_id
                ),
            )
            del request_context
            host._register_sms_transport(expected_task_id, transport)
    except BaseException:
        # Setup happens before the protocol-session ``finally`` below. If a
        # transport/context hook fails here, still drop the task-bound seed so
        # a later task cannot resolve another account's 2FA secret.
        host._oauth_mfa_runtime_ext.clear_task_secrets(
            host._TASK_TOTP_SECRETS,
            task_id_hint,
            bound_totp_task_id,
        )
        raise
    transport_token = host._ACTIVE_SMS_TRANSPORT.set(transport)
    protocol_activity_token = host._PROTOCOL_REQUEST_ACTIVITY.set(0)
    task_id = task_id_hint

    def record_protocol_wait(elapsed_seconds):
        host._record_task_segment(
            task_id,
            "protocol_slot_waiting",
            elapsed_seconds,
        )

    def log_protocol_limit_change(event):
        value = dict(event or {})
        old_limit = int(value.get("old_limit") or 0)
        new_limit = int(value.get("new_limit") or 0)
        if old_limit <= 0 or new_limit <= 0 or old_limit == new_limit:
            return
        restored = str(value.get("kind") or "") == "restored"
        reason = "连续成功后恢复" if restored else "60 秒内连接压力达到阈值"
        host._call_log(
            log_fn,
            f"  [并发保护] 协议并发 {old_limit} -> {new_limit}（{reason}）",
            "info" if restored else "warn",
        )

    staged_pipeline = host._inflight_pipeline_runtime_ext.optimization_active(
        host._CURRENT_INFLIGHT_GATE
    ) and str(runtime_config.get("run_mode") or "register").strip().lower() != "relogin"
    try:
        with host._inflight_pipeline_runtime_ext.protocol_session_scope(
            staged=staged_pipeline,
            gate=host._PROTOCOL_GATE,
            proxy=proxy,
            stop_event=runtime_config.get("_stop_requested"),
            on_wait=record_protocol_wait,
        ):
            try:
                result = host._ORIGINAL_RUN_CODEX_AFTER_REGISTRATION(
                    oauth_url=oauth_url,
                    code_verifier=code_verifier,
                    account_email=account_email,
                    password=password,
                    phase1_register=phase1_register,
                    phase1_response=phase1_response,
                    phase1_continue_url=phase1_continue_url,
                    sms_provider=sms_provider,
                    config=runtime_config,
                    proxy=proxy,
                    email_proxy=email_proxy,
                    upload_proxy=upload_proxy,
                    log_fn=log_fn,
                    mode=mode,
                    local_oauth_client_id=local_oauth_client_id,
                    local_oauth_redirect_uri=local_oauth_redirect_uri,
                    oauth_provider=oauth_provider,
                    oauth_session_id=oauth_session_id,
                    oauth_state=oauth_state,
                    upload_target_name=upload_target_name,
                    node_result=node_result,
                    runtime_context_expected=runtime_context_expected,
                    runtime_context_strict=runtime_context_strict,
                    transport=transport,
                    sentinel_provider=sentinel_provider,
                    email_otp_provider=email_otp_provider,
                    phone_otp_provider=phone_otp_provider,
                )
            except Exception as exc:
                main_chain_pressure, pressure_failure = host._is_main_chain_pressure_source(
                    task_id,
                    exc,
                )
                has_request_activity = host._PROTOCOL_REQUEST_ACTIVITY.get() > 0
                if main_chain_pressure and not has_request_activity:
                    host._PROTOCOL_COORDINATOR.observe_main_chain_outcome(
                        exc,
                        succeeded=False,
                        task_id=task_id,
                        proxy=proxy,
                        failure=pressure_failure,
                        on_limit_change=log_protocol_limit_change,
                    )
                raise
            else:
                failure_value = result
                if isinstance(result, dict):
                    failure_value = " ".join(
                        str(result.get(key) or "")
                        for key in ("error", "technical_error", "phase2_error")
                    )
                succeeded = bool(isinstance(result, dict) and result.get("ok"))
                main_chain_pressure, pressure_failure = host._is_main_chain_pressure_source(
                    task_id,
                    result if isinstance(result, dict) else failure_value,
                )
                pressure_signal_value = (
                    result if isinstance(result, dict) else failure_value
                )
                has_request_activity = host._PROTOCOL_REQUEST_ACTIVITY.get() > 0
                if (succeeded or main_chain_pressure) and not has_request_activity:
                    host._PROTOCOL_COORDINATOR.observe_main_chain_outcome(
                        pressure_signal_value,
                        succeeded=succeeded,
                        task_id=task_id,
                        proxy=proxy,
                        failure=pressure_failure,
                        on_limit_change=log_protocol_limit_change,
                    )
    finally:
        runtime_config.pop("phase1_active_session", None)
        host._PROTOCOL_REQUEST_ACTIVITY.reset(protocol_activity_token)
        host._ACTIVE_SMS_TRANSPORT.reset(transport_token)
        host._oauth_mfa_runtime_ext.clear_task_secrets(
            host._TASK_TOTP_SECRETS,
            task_id,
            bound_totp_task_id,
        )
        if task_id and host._TASK_CONTEXT.get() != task_id:
            host._SMS_TRANSPORT_REGISTRY.close_task(task_id)
            host._AUTH_SESSIONS.clear(task_id)
    if isinstance(result, dict) and host._is_auth_session_reset_failure(result):
        result = dict(result)
        result["resume_stage"] = "fresh_oauth"
        runtime_config.pop("phase1_active_session", None)
        task_id = str(runtime_config.get("sms_task_id") or runtime_config.get("run_id") or "")
        if task_id:
            context = host._AUTH_SESSIONS.get(task_id, email=account_email)
            result["auth_session_invalid_count"] = int(context.invalidations)
            result["sms_platform_attempts"] = host._SMS_PROVIDER_REGISTRY.snapshot_task_attempt_counts(
                task_id
            )
    elif isinstance(result, dict):
        task_id = str(runtime_config.get("sms_task_id") or runtime_config.get("run_id") or "")
        if task_id:
            result = dict(result)
            result["sms_platform_attempts"] = host._SMS_PROVIDER_REGISTRY.snapshot_task_attempt_counts(
                task_id
            )
    if isinstance(result, dict) and result.get("ok"):
        host._clear_known_node_failure(str(runtime_config.get("sms_task_id") or ""))
    return result
