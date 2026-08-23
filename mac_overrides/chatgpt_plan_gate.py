"""ChatGPT plan detection and the paid SMS allocation gate."""

from __future__ import annotations

import base64
from collections.abc import Callable, Mapping
from dataclasses import dataclass
import json
import re
from typing import Any


ACCOUNTS_CHECK_PATH = "/backend-api/accounts/check/v4-2023-04-27"

_UNKNOWN_PLANS = frozenset(
    {
        "",
        "0",
        "invalid",
        "missing",
        "na",
        "none",
        "notapplicable",
        "notavailable",
        "null",
        "undefined",
        "unknown",
        "unavailable",
    }
)


@dataclass(frozen=True)
class PlanDecision:
    allowed: bool
    plan_type: str = ""
    source: str = ""
    error_code: str = ""
    reason: str = ""
    http_status: int | None = None

    def error_message(self) -> str:
        return f"{self.error_code}: {self.reason}"


def _enabled(value: Any, default: bool = False) -> bool:
    if value is None or value == "":
        return bool(default)
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    return str(value).strip().lower() in {"1", "true", "yes", "on", "enabled"}


def normalize_token(token: Any) -> str:
    value = str(token or "").strip().strip('"').strip("'")
    if value.lower().startswith("authorization:"):
        value = value.split(":", 1)[1].strip()
    if value.lower().startswith("bearer "):
        value = value[7:].strip()
    return value


def decode_jwt_payload_unverified(token: Any) -> dict[str, Any]:
    value = normalize_token(token)
    try:
        parts = value.split(".")
        if len(parts) < 2:
            return {}
        payload = parts[1] + "=" * (-len(parts[1]) % 4)
        decoded = json.loads(base64.urlsafe_b64decode(payload.encode("ascii")))
    except Exception:
        return {}
    return dict(decoded) if isinstance(decoded, Mapping) else {}


def token_claims(token: Any) -> dict[str, str]:
    payload = decode_jwt_payload_unverified(token)
    auth = payload.get("https://api.openai.com/auth")
    auth = auth if isinstance(auth, Mapping) else {}
    profile = payload.get("https://api.openai.com/profile")
    profile = profile if isinstance(profile, Mapping) else {}
    return {
        "account_id": str(
            auth.get("chatgpt_account_id")
            or auth.get("account_id")
            or payload.get("chatgpt_account_id")
            or ""
        ).strip(),
        "plan_type": normalize_plan_type(
            auth.get("chatgpt_plan_type")
            or auth.get("plan_type")
            or payload.get("chatgpt_plan_type")
            or payload.get("plan_type")
            or profile.get("plan_type")
        ),
    }


def normalize_plan_type(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    text = value.strip().lower()
    compact = re.sub(r"[^a-z0-9]+", "", text)
    if compact in _UNKNOWN_PLANS:
        return ""
    if compact.startswith("chatgpt"):
        compact = compact[7:]
    if compact.endswith("plan"):
        compact = compact[:-4]
    if compact in _UNKNOWN_PLANS:
        return ""
    aliases = {
        "free": "free",
        "freeaccount": "free",
        "freeworkspace": "free",
        "go": "go",
        "plus": "plus",
        "pro": "pro",
        "prolite": "prolite",
        "team": "team",
        "business": "business",
        "enterprise": "enterprise",
        "edu": "edu",
        "education": "edu",
        "k12": "k12",
    }
    return aliases.get(compact, "")


def _http_status(value: Any) -> int | None:
    raw = (
        value.get("_status") or value.get("status_code")
        if isinstance(value, Mapping)
        else getattr(value, "status_code", None)
    )
    try:
        status = int(raw)
    except (TypeError, ValueError):
        return None
    return status if 100 <= status <= 599 else None


def plan_from_session(data: Any) -> tuple[str, str]:
    if not isinstance(data, Mapping):
        return "", ""
    account = data.get("account")
    account = account if isinstance(account, Mapping) else {}
    user = data.get("user")
    user = user if isinstance(user, Mapping) else {}
    entitlement = data.get("entitlement")
    entitlement = entitlement if isinstance(entitlement, Mapping) else {}
    candidates = (
        (account.get("planType"), "session.account.planType"),
        (account.get("plan_type"), "session.account.plan_type"),
        (data.get("planType"), "session.planType"),
        (data.get("plan_type"), "session.plan_type"),
        (user.get("planType"), "session.user.planType"),
        (user.get("plan_type"), "session.user.plan_type"),
        (entitlement.get("subscription_plan"), "session.entitlement.subscription_plan"),
        (entitlement.get("subscriptionPlan"), "session.entitlement.subscriptionPlan"),
    )
    for raw_plan, source in candidates:
        plan = normalize_plan_type(raw_plan)
        if plan:
            return plan, source
    return "", ""


def access_token_from_session(data: Any) -> str:
    if not isinstance(data, Mapping):
        return ""
    for key in ("accessToken", "access_token", "oauth_token", "session_token", "token"):
        token = normalize_token(data.get(key))
        if token:
            return token
    for key in ("session", "auth", "tokens"):
        nested = data.get(key)
        if isinstance(nested, Mapping):
            token = access_token_from_session(nested)
            if token:
                return token
    return ""


def plan_from_accounts_check(data: Any, *, token: Any = "") -> tuple[str, str]:
    if not isinstance(data, Mapping):
        raise ValueError("响应不是 JSON 对象")
    accounts = data.get("accounts")
    if not isinstance(accounts, Mapping):
        raise ValueError("响应缺少 accounts 对象")

    claims = token_claims(token)
    account_id = claims.get("account_id") or ""
    item: Any = accounts.get(account_id) if account_id else None
    if account_id and not isinstance(item, Mapping):
        # Do not silently inspect another account when the bearer token names
        # an account that the provider did not return. That can misclassify a
        # Plus account as a different workspace (or vice versa).
        default_item = accounts.get("default")
        if isinstance(default_item, Mapping):
            default_account = default_item.get("account")
            default_account = default_account if isinstance(default_account, Mapping) else {}
            default_id = str(
                default_account.get("account_id")
                or default_account.get("accountId")
                or default_item.get("account_id")
                or ""
            ).strip()
            # Some provider responses expose only a ``default`` entry and do
            # not repeat the account id inside it; accept that single-entry
            # shape while still rejecting an explicitly different id.
            if not default_id or default_id == account_id:
                item = default_item
        if not isinstance(item, Mapping):
            raise ValueError("Token 账号与套餐响应账号不匹配")
    if not isinstance(item, Mapping):
        item = accounts.get("default")
    if not isinstance(item, Mapping):
        item = next(
            (
                value
                for key, value in accounts.items()
                if key != "default" and isinstance(value, Mapping)
            ),
            None,
        )
    if not isinstance(item, Mapping):
        raise ValueError("未找到可解析的账号条目")

    account = item.get("account")
    account = account if isinstance(account, Mapping) else {}
    entitlement = item.get("entitlement")
    entitlement = entitlement if isinstance(entitlement, Mapping) else {}
    last_subscription = item.get("last_active_subscription")
    last_subscription = (
        last_subscription if isinstance(last_subscription, Mapping) else {}
    )
    account_plan = normalize_plan_type(
        account.get("plan_type")
        or account.get("planType")
        or item.get("plan_type")
        or item.get("planType")
    )
    subscription_plan = normalize_plan_type(
        entitlement.get("subscription_plan")
        or entitlement.get("subscriptionPlan")
        or last_subscription.get("subscription_plan")
        or last_subscription.get("subscriptionPlan")
        or item.get("subscription_plan")
    )
    has_active_subscription = _enabled(
        entitlement.get("has_active_subscription")
        if "has_active_subscription" in entitlement
        else item.get("has_active_subscription"),
        False,
    )
    if (
        subscription_plan
        and subscription_plan != "free"
        and has_active_subscription
    ):
        return subscription_plan, "accounts_check.entitlement.subscription_plan"
    if account_plan:
        return account_plan, "accounts_check.account.plan_type"
    if subscription_plan == "free":
        return subscription_plan, "accounts_check.entitlement.subscription_plan"
    claim_plan = claims.get("plan_type") or ""
    if claim_plan:
        return claim_plan, "access_token.chatgpt_plan_type"
    return "", ""


class ChatGptPlanGate:
    """Own session capture, plan lookup, and the pre-allocation gate."""

    def __init__(
        self,
        *,
        chatgpt_origin: str,
        json_response: Callable[[Any], Any],
        clean: Callable[[Any], Any],
        with_protocol_lease: Callable[[Any, Callable[[], Any]], Any],
        request_headers: Callable[..., dict[str, str]],
        active_transport: Callable[[], Any],
        transport_for_task: Callable[[str], Any],
        transport_task_id: Callable[[Any], str],
        prepare_phone_entry: Callable[..., Any],
        set_stage: Callable[[str], None],
        auth_context_error: type[BaseException],
        invalidate_auth_session: Callable[[Any, BaseException], None],
        chain_error: type[BaseException],
    ) -> None:
        self.chatgpt_origin = str(chatgpt_origin).rstrip("/")
        self.json_response = json_response
        self.clean = clean
        self.with_protocol_lease = with_protocol_lease
        self.request_headers = request_headers
        self.active_transport = active_transport
        self.transport_for_task = transport_for_task
        self.transport_task_id = transport_task_id
        self.prepare_phone_entry = prepare_phone_entry
        self.set_stage = set_stage
        self.auth_context_error = auth_context_error
        self.invalidate_auth_session = invalidate_auth_session
        self.chain_error = chain_error

    def _request_chatgpt_session(
        self,
        transport: Any,
    ) -> tuple[dict[str, Any], str, int | None]:
        response = transport.session.get(
            f"{self.chatgpt_origin}/api/auth/session",
            headers={"accept": "application/json"},
            timeout=30,
        )
        raw_data = self.json_response(response)
        data = dict(raw_data) if isinstance(raw_data, Mapping) else {}
        status = _http_status(data) or _http_status(response)
        token = normalize_token(self.clean(access_token_from_session(data)))
        plan, _source = plan_from_session(data)
        setattr(transport, "_gptphone_chatgpt_session", data)
        setattr(transport, "_gptphone_chatgpt_access_token", token)
        setattr(transport, "_gptphone_chatgpt_plan_type", plan)
        setattr(transport, "_gptphone_chatgpt_session_http_status", status)
        return data, token, status

    def capture_access_token(self, transport: Any) -> str:
        _data, token, _status = self.with_protocol_lease(
            transport,
            lambda: self._request_chatgpt_session(transport),
        )
        return token

    def _cached_session(self, transport: Any) -> dict[str, Any]:
        value = getattr(transport, "_gptphone_chatgpt_session", None)
        return dict(value) if isinstance(value, Mapping) else {}

    def _cached_token(self, transport: Any, session_data: Any) -> str:
        return normalize_token(
            getattr(transport, "_gptphone_chatgpt_access_token", "")
            or access_token_from_session(session_data)
        )

    @staticmethod
    def _token_from_mapping(value: Any) -> str:
        if not isinstance(value, Mapping):
            return ""
        for key in (
            "access_token", "accessToken", "oauth_token", "oauthToken",
            "oauth_access_token", "session_token", "sessionToken",
            "chatgpt_access_token", "chatgptAccessToken", "token",
        ):
            token = normalize_token(value.get(key))
            if token:
                return token
        for key in ("tokens", "oauth_tokens", "session", "auth", "result"):
            nested = value.get(key)
            if isinstance(nested, Mapping):
                token = ChatGptPlanGate._token_from_mapping(nested)
                if token:
                    return token
        return ""

    @classmethod
    def _transport_token(cls, transport: Any) -> str:
        """Read only already-captured task credentials; never request a new token here."""
        for name in _TRANSPORT_TOKEN_ATTRS:
            value = getattr(transport, name, "")
            if not callable(value):
                token = normalize_token(value)
                if token:
                    return token
        for name in (
            "_gptphone_last_response", "last_response", "last_result",
            "exchange_data", "tokens", "oauth_tokens", "_oauth_tokens",
        ):
            token = cls._token_from_mapping(getattr(transport, name, None))
            if token:
                return token
        return ""

    @staticmethod
    def _transient_status(status: int | None) -> bool:
        return status in {408, 409, 425, 429} or bool(status and status >= 500)

    @staticmethod
    def _transient_exception(error: BaseException) -> bool:
        """Only retry network/provider failures, never programming errors.

        The recovered runtime exposes several third-party HTTP exception types
        without guaranteeing a common base class. Matching their stable class
        names keeps this module dependency-free while avoiding retries for
        assertion/type errors that indicate a local integration bug.
        """
        if isinstance(error, (TimeoutError, OSError)):
            return True
        return type(error).__name__ in _TRANSIENT_EXCEPTION_NAMES

    @staticmethod
    def _retry_delay(config: Mapping[str, Any]) -> float:
        try:
            value = float(config.get("plan_check_retry_delay", 0.25) or 0.25)
        except (TypeError, ValueError):
            value = 0.25
        return max(0.0, min(5.0, value))

    @staticmethod
    def _retry_attempts(config: Mapping[str, Any]) -> int:
        """Return total attempts (initial request plus bounded retries)."""
        raw = config.get("plan_check_retries", 1)
        try:
            retries = int(raw)
        except (TypeError, ValueError):
            retries = 1
        return max(1, min(3, retries + 1))

    @staticmethod
    def _record_diagnostic(transport: Any, **values: Any) -> None:
        safe = {
            key: value for key, value in values.items()
            if key not in {"token", "access_token", "response", "body"}
        }
        safe["token_present"] = bool(values.get("token_present"))
        try:
            setattr(transport, "_gptphone_plan_check_diagnostics", safe)
        except Exception:
            pass
        log_fn = getattr(transport, "log_fn", None)
        if callable(log_fn):
            try:
                summary = ", ".join(f"{key}={value}" for key, value in safe.items())
                log_fn(f"[验证套餐等级/phone_plan_check] {summary}", "info")
            except Exception:
                pass

    @staticmethod
    def _cached_session_status(transport: Any, session_data: Any) -> int | None:
        status = _http_status(session_data)
        if status is not None:
            return status
        try:
            cached = int(
                getattr(transport, "_gptphone_chatgpt_session_http_status", 0) or 0
            )
        except (TypeError, ValueError):
            return None
        return cached if 100 <= cached <= 599 else None

    def _accounts_check_headers(self, transport: Any, token: str) -> dict[str, str]:
        headers = {
            "accept": "*/*",
            "authorization": f"Bearer {token}",
            "referer": f"{self.chatgpt_origin}/",
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-origin",
            "x-openai-target-path": ACCOUNTS_CHECK_PATH,
            "x-openai-target-route": ACCOUNTS_CHECK_PATH,
        }
        device_id = str(getattr(transport, "device_id", "") or "").strip()
        if device_id:
            headers["oai-device-id"] = device_id
        return self.request_headers(transport, headers, include_sentinel=False)

    def _query_accounts_check(
        self,
        transport: Any,
        token: str,
    ) -> tuple[str, str, str, int | None]:
        config = getattr(transport, "config", None)
        config = config if isinstance(config, Mapping) else {}
        attempts = self._retry_attempts(config)
        delay = self._retry_delay(config)
        last: tuple[str, str, str, int | None] = (
            "",
            "",
            "套餐复核未返回结果",
            None,
        )

        def request_once() -> tuple[str, str, str, int | None]:
            response = transport.session.get(
                f"{self.chatgpt_origin}{ACCOUNTS_CHECK_PATH}?timezone_offset_min=-",
                headers=self._accounts_check_headers(transport, token),
                allow_redirects=False,
                timeout=15,
            )
            try:
                status = int(getattr(response, "status_code", 0) or 0)
            except (TypeError, ValueError):
                status = 0
            try:
                data = self.json_response(response)
            except Exception:
                return "", "", "套餐复核响应不是有效 JSON", status or None
            if not 200 <= status < 300:
                detail = (
                    f"套餐复核返回 HTTP {status}"
                    if status
                    else "套餐复核未返回 HTTP 状态"
                )
                return "", "", detail, status or None
            try:
                plan, source = plan_from_accounts_check(data, token=token)
            except (TypeError, ValueError) as exc:
                return "", "", str(exc), status or None
            if not plan:
                return "", "", "套餐复核响应未包含可识别的套餐字段", status or None
            return plan, source, "", status or None

        for attempt in range(1, attempts + 1):
            previous = last
            try:
                last = self.with_protocol_lease(transport, request_once)
            except Exception as exc:
                # If a retry itself fails locally, preserve the provider HTTP
                # status and detail from the previous attempt for diagnosis.
                if previous[3] is not None:
                    last = ("", "", previous[2], previous[3])
                else:
                    last = (
                        "",
                        "",
                        f"套餐复核请求异常（{type(exc).__name__}）",
                        None,
                    )
                retryable = self._transient_exception(exc)
            else:
                retryable = self._transient_status(last[3])
            if last[0] or not retryable or attempt >= attempts:
                break
            if delay:
                time.sleep(delay * attempt)

        try:
            setattr(transport, "_gptphone_plan_check_attempt_count", attempt)
        except Exception:
            pass
        return last

    def evaluate_sms_binding(self, transport: Any) -> PlanDecision:
        """Compatibility no-op retained for callers outside ordinary SMS.

        Ordinary SMS no longer performs a ChatGPT plan lookup before requesting
        a phone number. Free registration owns its own plan/eligibility checks;
        this method is intentionally an unconditional allow for old callers.
        """
        return PlanDecision(True, source="ordinary_sms_plan_gate_removed")

    def preflight_sms_phone_context(self, _adapter: Any, task_id: Any) -> Any:
        expected_task_id = str(task_id or "").strip()
        transport = self.active_transport()
        if transport is not None and expected_task_id:
            if self.transport_task_id(transport) != expected_task_id:
                transport = None
        if transport is None:
            transport = self.transport_for_task(expected_task_id)
        if transport is None:
            self.set_stage("phone_submitting")
            raise self.chain_error(
                "auth_context_transport_missing: 当前任务没有可用的登录 Transport，已阻止申请手机号"
            )

        self.set_stage("phone_submitting")
        try:
            context = self.prepare_phone_entry(
                transport,
                expected_task_id=expected_task_id,
            )
        except self.auth_context_error as exc:
            self.invalidate_auth_session(transport, exc)
            raise self.chain_error(f"{exc.code}: {exc}") from exc

        decision = self.evaluate_sms_binding(transport)
        if not decision.allowed:
            raise self.chain_error(decision.error_message())
        self.set_stage("phone_acquiring")
        return context


__all__ = [
    "ACCOUNTS_CHECK_PATH",
    "ChatGptPlanGate",
    "PlanDecision",
    "access_token_from_session",
    "decode_jwt_payload_unverified",
    "normalize_plan_type",
    "normalize_token",
    "plan_from_accounts_check",
    "plan_from_session",
    "token_claims",
]
