"""ChatGPT plan detection and the paid SMS allocation gate."""

from __future__ import annotations

import base64
from collections.abc import Callable, Mapping
from dataclasses import dataclass
import json
import re
from typing import Any


ALLOW_FREE_PLAN_SMS_BINDING = "allow_free_plan_sms_binding"
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
    return {
        "account_id": str(auth.get("chatgpt_account_id") or "").strip(),
        "plan_type": normalize_plan_type(auth.get("chatgpt_plan_type")),
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
    candidates = (
        (account.get("planType"), "session.account.planType"),
        (account.get("plan_type"), "session.account.plan_type"),
        (data.get("planType"), "session.planType"),
        (data.get("plan_type"), "session.plan_type"),
        (user.get("planType"), "session.user.planType"),
        (user.get("plan_type"), "session.user.plan_type"),
    )
    for raw_plan, source in candidates:
        plan = normalize_plan_type(raw_plan)
        if plan:
            return plan, source
    return "", ""


def access_token_from_session(data: Any) -> str:
    if not isinstance(data, Mapping):
        return ""
    return normalize_token(data.get("accessToken") or data.get("access_token"))


def plan_from_accounts_check(data: Any, *, token: Any = "") -> tuple[str, str]:
    if not isinstance(data, Mapping):
        raise ValueError("响应不是 JSON 对象")
    accounts = data.get("accounts")
    if not isinstance(accounts, Mapping):
        raise ValueError("响应缺少 accounts 对象")

    claims = token_claims(token)
    account_id = claims.get("account_id") or ""
    item: Any = accounts.get(account_id) if account_id else None
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
    account_plan = normalize_plan_type(
        account.get("plan_type") or account.get("planType")
    )
    subscription_plan = normalize_plan_type(
        entitlement.get("subscription_plan") or entitlement.get("subscriptionPlan")
    )
    has_active_subscription = _enabled(
        entitlement.get("has_active_subscription"),
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
        def request() -> tuple[str, str, str, int | None]:
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
            data = self.json_response(response)
            if not 200 <= status < 300:
                detail = f"套餐复核返回 HTTP {status}" if status else "套餐复核未返回 HTTP 状态"
                return "", "", detail, status or None
            try:
                plan, source = plan_from_accounts_check(data, token=token)
            except (TypeError, ValueError) as exc:
                return "", "", str(exc), status
            if not plan:
                return "", "", "套餐复核响应未包含可识别的套餐字段", status
            return plan, source, "", status

        return self.with_protocol_lease(transport, request)

    @staticmethod
    def _allow(plan: str, source: str) -> PlanDecision:
        return PlanDecision(True, plan_type=plan, source=source)

    @staticmethod
    def _block_free(source: str) -> PlanDecision:
        return PlanDecision(
            False,
            plan_type="free",
            source=source,
            error_code="phone_plan_free_skipped",
            reason="当前账号套餐为 free，已按默认设置停止且未调用接码平台",
        )

    @staticmethod
    def _block_unknown(reason: str, http_status: int | None = None) -> PlanDecision:
        detail = str(reason or "套餐来源未返回可识别的套餐字段").strip()
        return PlanDecision(
            False,
            source="unknown",
            error_code="phone_plan_unknown_skipped",
            reason=f"{detail}，无法确认当前账号套餐，已按省成本设置停止且未调用接码平台",
            http_status=http_status,
        )

    def evaluate_sms_binding(self, transport: Any) -> PlanDecision:
        config = getattr(transport, "config", None)
        config = config if isinstance(config, Mapping) else {}
        if _enabled(config.get(ALLOW_FREE_PLAN_SMS_BINDING), False):
            return PlanDecision(True, source="config_bypass")

        session_data = self._cached_session(transport)
        session_status = self._cached_session_status(transport, session_data)
        if session_status is not None and not 200 <= session_status < 300:
            return self._block_unknown(
                f"ChatGPT session 查询返回 HTTP {session_status}",
                session_status,
            )
        plan, source = plan_from_session(session_data)
        if plan:
            return self._block_free(source) if plan == "free" else self._allow(plan, source)

        token = self._cached_token(transport, session_data)
        if not token:
            try:
                session_data, token, session_status = self.with_protocol_lease(
                    transport,
                    lambda: self._request_chatgpt_session(transport),
                )
            except Exception as exc:
                return self._block_unknown(
                    f"ChatGPT session 查询异常（{type(exc).__name__}）"
                )
            if session_status is not None and not 200 <= session_status < 300:
                return self._block_unknown(
                    f"ChatGPT session 查询返回 HTTP {session_status}",
                    session_status,
                )
            plan, source = plan_from_session(session_data)
            if plan:
                return self._block_free(source) if plan == "free" else self._allow(plan, source)

        claim_plan = token_claims(token).get("plan_type") or ""
        if claim_plan:
            source = "access_token.chatgpt_plan_type"
            return self._block_free(source) if claim_plan == "free" else self._allow(claim_plan, source)
        if not token:
            return self._block_unknown("ChatGPT session 未返回 accessToken")

        try:
            plan, source, detail, status = self._query_accounts_check(transport, token)
        except Exception as exc:
            return self._block_unknown(f"套餐复核请求异常（{type(exc).__name__}）")
        if plan:
            return self._block_free(source) if plan == "free" else self._allow(plan, source)
        return self._block_unknown(detail, status)

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

        self.set_stage("phone_acquiring")
        decision = self.evaluate_sms_binding(transport)
        if not decision.allowed:
            raise self.chain_error(decision.error_message())
        return context


__all__ = [
    "ACCOUNTS_CHECK_PATH",
    "ALLOW_FREE_PLAN_SMS_BINDING",
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
