"""Credential-safe SMS balance query route."""

from __future__ import annotations

import time
from typing import Any, Callable, Sequence

try:
    from .route_failures import explicit_failure_payload
except ImportError:  # Loaded as a top-level runtime override.
    from route_failures import explicit_failure_payload  # type: ignore[no-redef]


_CONFIG_KEYS = (
    "sms_provider_pools", "sms_provider", "sms_api_keys", "sms_api_key",
    "service", "sms_min_price", "max_price", "proxy", "proxy_scope",
)


class SmsBalanceRouteController:
    def __init__(
        self,
        *,
        module: Any,
        context: Any,
        secrets_for: Callable[[Any], Sequence[Any]],
    ) -> None:
        self.module = module
        self.context = context
        self.secrets_for = secrets_for

    def query(self):
        module = self.module
        if self.context.query_sms_balances is None:
            payload = explicit_failure_payload(
                node_code="sms_balance_query", node_label="查询接码余额",
                error_code="sms_balance_query_unavailable", cause="服务尚未启用",
                http_status=503,
            )
            return module.jsonify(payload), 503
        data = module.request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return module.jsonify(ok=False, error="配置必须是 JSON 对象"), 400
        try:
            local = self.context.read_local_config()
            config = {key: data[key] if key in data else local[key]
                      for key in _CONFIG_KEYS if key in data or key in local}
            statuses = self.context.query_sms_balances(config)
            return module.jsonify(
                ok=True,
                queried_at=int(time.time()),
                sms_key_statuses=statuses,
            )
        except ValueError as exc:
            payload = explicit_failure_payload(
                node_code="sms_balance_query", node_label="查询接码余额",
                error_code="sms_balance_query_failed",
                cause=self.context.safe_runtime_error(exc),
                secrets=self.secrets_for(data), http_status=400,
            )
            return module.jsonify(payload), 400
        except Exception as exc:
            payload = explicit_failure_payload(
                node_code="sms_balance_query", node_label="查询接码余额",
                error_code="sms_balance_query_failed",
                cause=f"接码平台请求异常（{type(exc).__name__}）",
                retryable=True, http_status=502,
                action_hint="检查接码平台 Key、代理和网络后重试。",
            )
            return module.jsonify(payload), 502


__all__ = ["SmsBalanceRouteController"]
