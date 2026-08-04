"""Update an existing SUB2 account without creating a duplicate row."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping
import urllib.parse


IDENTITY_KEYS = (
    "chatgpt_account_id",
    "account_id",
    "chatgpt_account_user_id",
    "chatgpt_user_id",
    "chatgpt_auth_user_id",
    "chatgpt_plan_type",
)


@dataclass(frozen=True)
class Sub2UpdateDependencies:
    get_admin_token: Callable[..., str]
    resolve_group: Callable[..., tuple[int, str]]
    fetch_detail: Callable[..., Mapping[str, Any]]
    assert_group: Callable[..., tuple[list[int], list[str]]]
    extract_fields: Callable[..., Mapping[str, Any]]
    extra_from_item: Callable[[Mapping[str, Any]], Mapping[str, Any]]
    identity_locations: Callable[[Mapping[str, Any]], tuple[str, str]]
    put: Callable[..., Any]
    requests_kwargs: Callable[[str], Mapping[str, Any]]


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _failure(
    code: str,
    message: str,
    account_id: str,
    *,
    http_status: int | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "ok": False,
        "error": f"{code}: {message}",
        "error_code": code,
        "sub2api_account_id": account_id,
        "sub2_update_existing": True,
        "sub2_upload_created": False,
    }
    if http_status is not None:
        result["http_status"] = int(http_status)
    return result


def _detail_data(value: Any) -> dict[str, Any]:
    current = dict(value) if isinstance(value, Mapping) else {}
    nested = current.get("data")
    if isinstance(nested, Mapping):
        current = dict(nested)
    for key in ("account", "item"):
        nested = current.get(key)
        if isinstance(nested, Mapping):
            current = dict(nested)
            break
    return current


def _bound_email(value: Any) -> str:
    detail = _detail_data(value)
    sources = [detail]
    for key in ("credentials", "extra"):
        nested = detail.get(key)
        if isinstance(nested, Mapping):
            sources.append(nested)
    for source in sources:
        for key in ("name", "email"):
            candidate = _clean(source.get(key)).lower()
            if "@" in candidate:
                return candidate
    return ""


def _bound_account_id(value: Any) -> str:
    detail = _detail_data(value)
    return _clean(detail.get("id") or detail.get("sub2api_account_id"))


def _response_json(response: Any) -> dict[str, Any]:
    try:
        value = response.json()
    except Exception:
        return {}
    return dict(value) if isinstance(value, Mapping) else {}


def _response_ok(response: Any, payload: Mapping[str, Any]) -> tuple[bool, int]:
    try:
        status_code = int(getattr(response, "status_code", 0) or 0)
    except (TypeError, ValueError):
        status_code = 0
    api_code = payload.get("code")
    return 200 <= status_code < 300 and api_code in (None, 0), status_code


def _binding_matches(detail: Any, account_id: str, email: str) -> bool:
    remote_id = _bound_account_id(detail)
    remote_email = _bound_email(detail)
    return bool(
        (not remote_id or remote_id == account_id)
        and remote_email
        and remote_email == email.lower()
    )


def update_existing_sub2_account(
    *,
    config: Mapping[str, Any],
    credentials: Mapping[str, Any],
    email: str,
    account_id: Any,
    upload_proxy: str,
    log_fn: Callable[[str, str], None] | None,
    dependencies: Sub2UpdateDependencies,
) -> dict[str, Any]:
    """Replace OAuth credentials on a known SUB2 row and verify the same row."""

    remote_id = _clean(account_id)
    normalized_email = _clean(email).lower()
    sub = config.get("sub2api") if isinstance(config.get("sub2api"), Mapping) else {}
    base = _clean(sub.get("url")).rstrip("/")
    admin_email = _clean(sub.get("email"))
    admin_password = _clean(sub.get("pwd") or sub.get("password"))
    group_name = _clean(sub.get("group")) or "CHATGPT"
    if not remote_id or not normalized_email:
        return _failure("sub2_update_binding_missing", "SUB2 原账号绑定信息缺失", remote_id)
    if not base or not admin_email or not admin_password:
        return _failure("sub2_update_config_missing", "SUB2 管理员配置不完整", remote_id)
    if any(not _clean(credentials.get(key)) for key in ("access_token", "refresh_token", "id_token")):
        return _failure("sub2_update_token_incomplete", "用于更新的 OAuth Token 不完整", remote_id)

    credentials_payload: dict[str, Any] = {
        "id_token": credentials.get("id_token") or "",
        "access_token": credentials.get("access_token") or "",
        "refresh_token": credentials.get("refresh_token") or "",
        "expires_at": credentials.get("expires_at") or 0,
        "email": normalized_email,
    }
    try:
        fields = dict(
            dependencies.extract_fields(
                credentials_payload,
                exchange_data=dict(credentials),
            )
            or {}
        )
        extra_source = dict(credentials)
        extra_source.update(fields)
        extra = dict(dependencies.extra_from_item(extra_source) or {})
        extra["email"] = normalized_email
        for key in IDENTITY_KEYS:
            value = _clean(fields.get(key))
            if value:
                credentials_payload[key] = value
                extra[key] = value
        chatgpt_account_id = _clean(fields.get("chatgpt_account_id"))
        if chatgpt_account_id:
            credentials_payload["chatgpt_account_id"] = chatgpt_account_id
            credentials_payload["account_id"] = chatgpt_account_id
            extra["chatgpt_account_id"] = chatgpt_account_id
            extra["account_id"] = chatgpt_account_id

        admin_token = dependencies.get_admin_token(
            base,
            admin_email,
            admin_password,
            timeout=30,
            log_fn=log_fn,
            proxy=upload_proxy,
        )
        group_id, resolved_group_name = dependencies.resolve_group(
            base,
            admin_token,
            group_name,
            attempts=3,
            timeout=15,
            log_fn=log_fn,
            proxy=upload_proxy,
        )
        current = dependencies.fetch_detail(
            base,
            admin_token,
            remote_id,
            log_fn=log_fn,
            proxy=upload_proxy,
        )
    except Exception:
        return _failure("sub2_update_prepare_failed", "SUB2 原账号更新准备失败", remote_id)

    if not current:
        return _failure("sub2_update_target_missing", "SUB2 原账号不存在，已停止且未创建新账号", remote_id)
    if not _binding_matches(current, remote_id, normalized_email):
        return _failure(
            "sub2_update_binding_mismatch",
            "SUB2 原账号与当前邮箱不匹配，已停止且未创建新账号",
            remote_id,
        )

    current_data = _detail_data(current)
    current_credentials = current_data.get("credentials")
    merged_credentials = dict(current_credentials) if isinstance(current_credentials, Mapping) else {}
    merged_credentials.update(credentials_payload)
    current_extra = current_data.get("extra")
    merged_extra = dict(current_extra) if isinstance(current_extra, Mapping) else {}
    merged_extra.update(extra)

    if log_fn is not None:
        try:
            log_fn("  [SUB2] 401/404 重跑正在更新原账号，不创建新账号", "info")
        except Exception:
            pass
    try:
        response = dependencies.put(
            f"{base}/api/v1/admin/accounts/{urllib.parse.quote(remote_id, safe='')}",
            json={"credentials": merged_credentials, "extra": merged_extra},
            headers={"Authorization": f"Bearer {admin_token}"},
            timeout=30,
            **dict(dependencies.requests_kwargs(upload_proxy) or {}),
        )
    except Exception:
        return _failure("sub2_update_existing_failed", "SUB2 原账号更新请求失败", remote_id)

    update_payload = _response_json(response)
    update_ok, http_status = _response_ok(response, update_payload)
    if not update_ok:
        return _failure(
            "sub2_update_existing_failed",
            f"SUB2 原账号更新失败（HTTP {http_status or 'unknown'}）",
            remote_id,
            http_status=http_status or None,
        )

    try:
        refreshed = dependencies.fetch_detail(
            base,
            admin_token,
            remote_id,
            log_fn=log_fn,
            proxy=upload_proxy,
        )
    except Exception:
        refreshed = {}
    if not refreshed or not _binding_matches(refreshed, remote_id, normalized_email):
        return _failure(
            "sub2_update_verification_failed",
            "SUB2 原账号更新后回查失败",
            remote_id,
        )

    try:
        actual_group_ids, actual_group_names = dependencies.assert_group(
            [update_payload, refreshed],
            int(group_id),
            str(resolved_group_name),
            allow_unknown=False,
        )
    except Exception:
        return _failure(
            "sub2_update_group_verification_failed",
            "SUB2 原账号更新后分组校验失败",
            remote_id,
        )

    try:
        remote_fields = dict(dependencies.extract_fields({}, exchange_data=refreshed) or {})
        remote_chatgpt_id = _clean(remote_fields.get("chatgpt_account_id"))
        credentials_id, extra_id = dependencies.identity_locations(refreshed)
    except Exception:
        remote_chatgpt_id = ""
        credentials_id = ""
        extra_id = ""
    expected_chatgpt_id = chatgpt_account_id or remote_chatgpt_id
    identity_verified = bool(
        expected_chatgpt_id
        and remote_chatgpt_id == expected_chatgpt_id
        and _clean(credentials_id) == expected_chatgpt_id
        and _clean(extra_id) == expected_chatgpt_id
    )
    if not identity_verified:
        return _failure(
            "sub2_update_identity_verification_failed",
            "SUB2 原账号更新后 OpenAI 身份校验失败",
            remote_id,
        )

    return {
        "ok": True,
        "sub2api_account_id": remote_id,
        "sub2api_group_id": int(group_id),
        "sub2api_group_name": str(resolved_group_name),
        "sub2api_group_ids": list(actual_group_ids),
        "sub2api_group_names": list(actual_group_names),
        "sub2_remote_verified": True,
        "sub2_group_verified": True,
        "chatgpt_account_id": expected_chatgpt_id,
        "account_id": expected_chatgpt_id,
        "sub2_chatgpt_account_id_verified": True,
        "sub2_chatgpt_account_id_backfilled": True,
        "sub2_chatgpt_account_id_import_updated": False,
        "sub2_update_existing": True,
        "sub2_upload_created": False,
    }


__all__ = ["Sub2UpdateDependencies", "update_existing_sub2_account"]
