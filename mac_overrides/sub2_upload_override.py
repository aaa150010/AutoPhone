"""SUB2 upload routing for first-run, rerun update, and confirmed missing targets."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any


def _confirmed_log(owner: Any, result: Any, *, binding_runtime: Any, call_log: Callable[..., Any]) -> None:
    confirmation = binding_runtime.confirmed_upload_log(result)
    if confirmation:
        call_log(getattr(owner, "log_fn", None), confirmation, "success")


def upload_sub2_with_relogin_policy(
    owner: Any,
    *,
    credentials: Mapping[str, Any],
    email: str,
    original_upload: Callable[..., Any],
    identity_locations: Callable[..., Any],
    update_runtime: Any,
    binding_runtime: Any,
    sub2_runtime: Any = None,
    direct_runtime: Any = None,
    call_log: Callable[..., Any],
) -> Any:
    config = getattr(owner, "config", None)
    binding = config.get("_sub2_update_existing") if isinstance(config, dict) else None
    relogin = isinstance(config, dict) and str(config.get("run_mode") or "").strip().lower() == "relogin"
    if relogin and not (isinstance(binding, dict) and str(binding.get("account_id") or "").strip()):
        return {
            "ok": False,
            "error": "relogin_sub2_binding_missing: 重登缺少 SUB2 原账号绑定，已停止且未创建新账号",
            "error_code": "relogin_sub2_binding_missing",
            "sub2_update_existing": True,
            "sub2_upload_created": False,
        }

    if not (isinstance(binding, dict) and str(binding.get("account_id") or "").strip()):
        result = original_upload(owner, credentials=credentials, email=email)
        _confirmed_log(owner, result, binding_runtime=binding_runtime, call_log=call_log)
        return result

    remote_id = str(binding.get("account_id") or "").strip()
    expected_email = str(binding.get("email") or "").strip().lower()
    if expected_email != str(email or "").strip().lower():
        return {
            "ok": False,
            "error": "sub2_update_binding_mismatch: SUB2 原账号与当前邮箱不匹配",
            "error_code": "sub2_update_binding_mismatch",
            "sub2api_account_id": remote_id,
            "sub2_update_existing": True,
            "sub2_upload_created": False,
        }

    import chatgpt_fields
    import proxy_scope
    import requests
    import sub2_groups
    import sub2_session

    dependencies = update_runtime.Sub2UpdateDependencies(
        get_admin_token=sub2_session.get_admin_token,
        resolve_group=sub2_groups.resolve_sub2_group_id,
        fetch_detail=chatgpt_fields.fetch_sub2_account_detail,
        assert_group=sub2_groups.assert_sub2_account_group,
        extract_fields=chatgpt_fields.extract_chatgpt_auth_fields,
        extra_from_item=chatgpt_fields.sub2_extra_from_item,
        identity_locations=identity_locations,
        put=requests.put,
        requests_kwargs=proxy_scope.requests_kwargs,
    )
    result = update_runtime.update_existing_sub2_account(
        config=config,
        credentials=credentials,
        email=email,
        account_id=remote_id,
        upload_proxy=str(getattr(owner, "upload_proxy", "") or ""),
        log_fn=getattr(owner, "log_fn", None),
        dependencies=dependencies,
    )
    if isinstance(result, Mapping) and result.get("error_code") == "sub2_update_target_missing":
        call_log(
            getattr(owner, "log_fn", None),
            "  [SUB2] 原账号已确认不存在，使用本次重登凭据创建新账号",
            "warn",
        )
        result = original_upload(owner, credentials=credentials, email=email)
        if isinstance(result, Mapping):
            result = dict(result)
            result["sub2_recreated_missing_target"] = bool(result.get("ok"))

    binding_runtime.clear_successful_update_statuses(
        binding,
        result,
        sub2_runtime=sub2_runtime,
        direct_runtime=direct_runtime,
    )
    _confirmed_log(owner, result, binding_runtime=binding_runtime, call_log=call_log)
    return result


__all__ = ["upload_sub2_with_relogin_policy"]
