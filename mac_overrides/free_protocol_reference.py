"""Reference browser identity and HTTP session preparation for Free protocol runs.

This module owns the AutoRegister-compatible browser/TLS identity.  It has no
network calls and deliberately exposes only safe fingerprint metadata to the
caller; cookies and proxy values stay inside the private transport session.
"""

from __future__ import annotations

from datetime import datetime
import secrets
from typing import Any, Mapping
from zoneinfo import ZoneInfo

try:
    from .free_protocol_bootstrap import REFERENCE_SENTINEL_VERSION
    from .free_register_common import FreeRegisterError
except ImportError:  # pragma: no cover
    from free_protocol_bootstrap import REFERENCE_SENTINEL_VERSION  # type: ignore[no-redef]
    from free_register_common import FreeRegisterError  # type: ignore[no-redef]


REFERENCE_FLOW_PROFILE = "reference_20260823"
REFERENCE_TLS_IMPERSONATE = "chrome146"
REFERENCE_LOCALES: dict[str, dict[str, Any]] = {
    "US": {
        "navigator_language": "en-US",
        "navigator_languages": ["en-US"],
        "accept_language": "en-US,en;q=0.9",
        "timezone_iana": "America/Los_Angeles",
    },
    "JP": {
        "navigator_language": "ja-JP",
        "navigator_languages": ["ja-JP"],
        "accept_language": "ja-JP,ja;q=0.9,en-US;q=0.8,en;q=0.7",
        "timezone_iana": "Asia/Tokyo",
    },
    "GB": {
        "navigator_language": "en-GB",
        "navigator_languages": ["en-GB"],
        "accept_language": "en-GB,en-US;q=0.9,en;q=0.8",
        "timezone_iana": "Europe/London",
    },
}


def reference_flow_enabled(config: Mapping[str, Any]) -> bool:
    return str(config.get("flow_profile") or REFERENCE_FLOW_PROFILE).strip().lower() != "legacy"


def timezone_profile(timezone_name: str, fallback: int = 0) -> tuple[str, int]:
    try:
        offset = datetime.now(ZoneInfo(timezone_name)).utcoffset()
    except Exception:
        offset = None
    return timezone_name, int(offset.total_seconds() // 60) if offset is not None else int(fallback)


def trace_profile() -> dict[str, str]:
    trace_id = str(secrets.randbelow((1 << 63) - 1) + 1)
    parent_id = str(secrets.randbelow((1 << 63) - 1) + 1)
    return {
        "datadog_origin": "rum",
        "datadog_sampling_priority": "1",
        "datadog_trace_id": trace_id,
        "datadog_parent_id": parent_id,
        "traceparent": f"00-{int(trace_id):032x}-{int(parent_id):016x}-01",
        "tracestate": "dd=s:1;o:rum",
    }


def reference_fingerprint(config: Mapping[str, Any], task: Mapping[str, Any]) -> dict[str, Any]:
    country = str(task.get("proxy_country") or "US").strip().upper()[:2]
    locale = dict(REFERENCE_LOCALES.get(country, REFERENCE_LOCALES["GB"]))
    timezone_name, timezone_offset = timezone_profile(str(locale["timezone_iana"]))
    protocol = config.get("protocol") if isinstance(config.get("protocol"), Mapping) else {}
    sentinel_version = str(protocol.get("sentinel_version") or REFERENCE_SENTINEL_VERSION).strip() or REFERENCE_SENTINEL_VERSION
    profile = {
        "browser_family": "chrome",
        "browser_os": "macOS",
        "chrome_major": "149",
        "chrome_full_version": "149.0.0.0",
        "user_agent": str(config.get("user_agent") or "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36"),
        "navigator_language": locale["navigator_language"],
        "navigator_languages": list(locale["navigator_languages"]),
        "accept_language": locale["accept_language"],
        "timezone_iana": timezone_name,
        "timezone_name": timezone_name,
        "timezone_offset_minutes": timezone_offset,
        "navigator_platform": "MacIntel",
        "navigator_vendor": "Google Inc.",
        "user_agent_data_platform": "macOS",
        "send_client_hints": True,
        "sec_ch_ua": '"Google Chrome";v="149", "Chromium";v="149", "Not)A;Brand";v="24"',
        "sec_ch_ua_full_version_list": '"Google Chrome";v="149.0.0.0", "Chromium";v="149.0.0.0", "Not)A;Brand";v="24.0.0.0"',
        "sec_ch_ua_platform": '"macOS"',
        "sec_ch_ua_platform_version": '"15.7.0"',
        "sec_ch_ua_mobile": "?0",
        "sec_ch_ua_arch": '"arm"',
        "sec_ch_ua_bitness": '"64"',
        "sec_ch_ua_model": '""',
        "screen_width": 1680,
        "screen_height": 1050,
        "device_pixel_ratio": 2,
        "hardware_concurrency": 6,
        "device_memory": 8,
        "js_heap_size_limit": 4395630592,
        "country": country,
        "sentinel_version": sentinel_version,
        "script_src_samples": [
            "https://accounts.google.com/gsi/client",
            "https://chatgpt.com/cdn-cgi/challenge-platform/scripts/jsd/api.js?onload=jsdOnload",
            f"https://sentinel.openai.com/sentinel/{sentinel_version}/sdk.js",
        ],
    }
    profile.update(trace_profile())
    return profile


def apply_geo_fingerprint(fingerprint: dict[str, Any], geo: Mapping[str, Any]) -> None:
    country = str(geo.get("country") or "").strip().upper()[:2]
    timezone = str(geo.get("timezone") or "").strip()[:100]
    if country:
        locale = REFERENCE_LOCALES.get(country, REFERENCE_LOCALES["GB"])
        fingerprint.update({
            "country": country,
            "navigator_language": locale["navigator_language"],
            "navigator_languages": list(locale["navigator_languages"]),
            "accept_language": locale["accept_language"],
        })
        if not timezone:
            timezone_name, timezone_offset = timezone_profile(str(locale["timezone_iana"]))
            fingerprint.update({
                "timezone_iana": timezone_name,
                "timezone_name": timezone_name,
                "timezone_offset_minutes": timezone_offset,
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


def copy_session_cookies(source: Any, target: Any) -> None:
    source_cookies = getattr(source, "cookies", None)
    target_cookies = getattr(target, "cookies", None)
    if source_cookies is None or target_cookies is None:
        return
    updater = getattr(target_cookies, "update", None)
    if callable(updater):
        try:
            updater(source_cookies)
            return
        except Exception:
            pass
    setter = getattr(target_cookies, "set", None)
    if not callable(setter):
        return
    for cookie in getattr(source_cookies, "jar", None) or ():
        try:
            setter(
                str(getattr(cookie, "name", "") or ""),
                str(getattr(cookie, "value", "") or ""),
                domain=str(getattr(cookie, "domain", "") or ""),
                path=str(getattr(cookie, "path", "/") or "/"),
            )
        except Exception:
            continue


def prepare_reference_http_session(transport: Any) -> Any:
    """Use AutoRegister's TLS image before the first Free protocol request."""
    current = getattr(transport, "session", None)
    creator = getattr(transport, "_new_session", None)
    session = current
    if callable(creator):
        try:
            try:
                session = creator(REFERENCE_TLS_IMPERSONATE)
            except TypeError:
                session = creator(impersonate=REFERENCE_TLS_IMPERSONATE)
        except Exception as exc:
            raise FreeRegisterError(
                "free_protocol_preflight", "协议网络预检",
                f"创建 {REFERENCE_TLS_IMPERSONATE} TLS 会话失败：{type(exc).__name__}",
                retryable=True,
                error_code="free_protocol_tls_session_failed",
                action_hint="确认 bundled curl_cffi 支持 chrome146 后重试",
            ) from exc
        if session is None:
            raise FreeRegisterError(
                "free_protocol_preflight", "协议网络预检",
                f"创建 {REFERENCE_TLS_IMPERSONATE} TLS 会话失败：未返回会话对象",
                retryable=True,
                error_code="free_protocol_tls_session_missing",
                action_hint="确认 bundled curl_cffi 支持 chrome146 后重试",
            )
        if session is not current:
            copy_session_cookies(current, session)
            setattr(transport, "session", session)
            close = getattr(current, "close", None)
            if callable(close):
                try:
                    close()
                except Exception:
                    pass
    if session is None:
        return transport
    try:
        session.trust_env = False
    except Exception:
        pass
    try:
        session.verify = True
    except Exception:
        pass
    old_proxies = getattr(current, "proxies", None)
    proxy = str(getattr(transport, "proxy", "") or "").strip()
    try:
        if isinstance(old_proxies, Mapping) and old_proxies:
            session.proxies = dict(old_proxies)
        elif proxy:
            session.proxies = {"http": proxy, "https": proxy}
    except Exception:
        pass
    timeout = getattr(current, "timeout", None)
    if timeout is not None:
        try:
            session.timeout = timeout
        except Exception:
            pass
    setattr(transport, "chatgpt_impersonate", REFERENCE_TLS_IMPERSONATE)
    setattr(transport, "_gptphone_tls_impersonate", REFERENCE_TLS_IMPERSONATE)
    return transport


def mark_reference_session_prepared(transport: Any) -> None:
    setattr(transport, "chatgpt_signup_done", True)
    setattr(transport, "_gptphone_reference_session_prepared", True)


__all__ = [
    "REFERENCE_FLOW_PROFILE", "REFERENCE_TLS_IMPERSONATE", "REFERENCE_SENTINEL_VERSION",
    "reference_flow_enabled", "reference_fingerprint", "apply_geo_fingerprint",
    "prepare_reference_http_session", "mark_reference_session_prepared",
]
