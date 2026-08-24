"""Isolated proxy and network diagnostics service.

The service intentionally has no dependency on either Free's proxy pool or the
ordinary SMS runtime.  A proxy selected for a test is the only proxy used for
that test; failures never fall back to the host proxy or another record.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path
import re
import socket
import threading
import time
from typing import Any, Callable, Mapping
from urllib.parse import quote, unquote, urlsplit

try:
    from .free_register_common import atomic_write, mask_proxy
    from .network_mihomo import IsolatedMihomo
except ImportError:
    from free_register_common import atomic_write, mask_proxy  # type: ignore[no-redef]
    from network_mihomo import IsolatedMihomo  # type: ignore[no-redef]


SUPPORTED_SCHEMES = frozenset({"http", "https", "socks4", "socks5", "socks5h"})
DEFAULT_NETWORK_CONFIG = {
    "version": 1,
    "workers": 3,
    "default_target_url": "https://www.google.com/generate_204",
    "default_exit_url": "https://api.ipify.org?format=json",
    "connect_timeout_seconds": 10,
    "request_timeout_seconds": 30,
    "mihomo_path": "/Applications/Clash Verge.app/Contents/MacOS/verge-mihomo",
}


class NetworkToolError(RuntimeError):
    def __init__(self, code: str, label: str, message: str, *, retryable: bool = True) -> None:
        super().__init__(message)
        self.node_code = code
        self.node_label = label
        self.error_code = f"{code}_failed"
        self.retryable = retryable


def _text(value: Any, limit: int = 500) -> str:
    return " ".join(str(value or "").split())[:limit]


def _safe_failure(value: Any) -> str:
    text = _text(value, 240)
    text = re.sub(r"(?i)(https?|socks[45]h?)://[^\s/@:]+:[^\s/@]+@", r"\1://", text)
    return re.sub(r"(?i)(password|passwd|token|authorization)\s*[=:]\s*[^\s,;]+", r"\1=[已隐藏]", text)


def _fingerprint(host: str, port: int, username: str, password: str) -> str:
    raw = f"{host}\0{port}\0{username}\0{password}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:16]


def _country(value: Any) -> str:
    normalized = _text(value, 2).upper()
    return normalized if len(normalized) == 2 and normalized.isalpha() else "ZZ"


def _parse_proxy(line: str, *, default_scheme: str = "http") -> dict[str, Any]:
    raw = line.strip()
    if not raw or raw.startswith("#"):
        raise ValueError("空代理行")
    scheme = default_scheme.lower().strip() or "http"
    # Keep compatibility with the common host:port:user:password import form.
    if "://" not in raw and raw.count(":") == 3:
        host, port_text, username, password = raw.split(":", 3)
        try:
            port = int(port_text)
        except ValueError as exc:
            raise ValueError("代理端口无效") from exc
        if not host or not (1 <= port <= 65535):
            raise ValueError("代理必须包含有效主机和端口")
        if scheme not in SUPPORTED_SCHEMES:
            raise ValueError(f"不支持的代理协议：{scheme}")
        return {
            "proxy_id": _fingerprint(host, port, username, password),
            "host": host,
            "port": port,
            "username": username,
            "password": password,
            "scheme": scheme,
        }
    candidate = raw if "://" in raw else f"{scheme}://{raw}"
    parsed = urlsplit(candidate)
    actual_scheme = parsed.scheme.lower()
    if actual_scheme not in SUPPORTED_SCHEMES:
        raise ValueError(f"不支持的代理协议：{actual_scheme}")
    if not parsed.hostname or parsed.port is None or not (1 <= parsed.port <= 65535):
        raise ValueError("代理必须包含有效主机和端口")
    username = unquote(parsed.username or "")
    password = unquote(parsed.password or "")
    host = parsed.hostname
    port = int(parsed.port)
    return {
        "proxy_id": _fingerprint(host, port, username, password),
        "host": host,
        "port": port,
        "username": username,
        "password": password,
        "scheme": actual_scheme,
    }


def _proxy_url(row: Mapping[str, Any]) -> str:
    auth = ""
    if row.get("username"):
        auth = quote(str(row.get("username")), safe="")
        if row.get("password"):
            auth += ":" + quote(str(row.get("password")), safe="")
        auth += "@"
    return f"{row.get('scheme', 'http')}://{auth}{row.get('host')}:{int(row.get('port'))}"


def _public(row: Mapping[str, Any]) -> dict[str, Any]:
    result = {
        key: copy.deepcopy(row.get(key))
        for key in (
            "proxy_id", "scheme", "country", "group", "enabled", "status", "lease_owner",
            "lease_until", "last_checked_at", "last_exit_ip", "latency_ms", "consecutive_failures",
            "last_failure", "source", "subscription_id",
        )
    } | {
        "masked": mask_proxy(_proxy_url(row)),
        "fingerprint": str(row.get("proxy_id") or ""),
    }
    result["last_failure"] = _safe_failure(result.get("last_failure")) if result.get("last_failure") else None
    return result


class NetworkToolsService:
    def __init__(
        self,
        data_root: str | Path,
        *,
        session_factory: Callable[[], Any] | None = None,
        socket_factory: Callable[..., Any] = socket.create_connection,
    ) -> None:
        self.data_dir = Path(data_root).expanduser().resolve() / "network_tools"
        self.proxies_path = self.data_dir / "proxies.json"
        self.subscriptions_path = self.data_dir / "subscriptions.json"
        self.config_path = self.data_dir / "config.json"
        self._lock = threading.RLock()
        self._session_factory = session_factory
        self._socket_factory = socket_factory
        self._config = self._load(self.config_path, "config", DEFAULT_NETWORK_CONFIG)
        self._proxies = self._load(self.proxies_path, "proxies", {})
        self._subscriptions = self._load(self.subscriptions_path, "subscriptions", {})
        self._normalize_loaded()

    @staticmethod
    def _load(path: Path, key: str, default: Any) -> Any:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError):
            return copy.deepcopy(default)
        if key == "config":
            return {**copy.deepcopy(default), **(value if isinstance(value, Mapping) else {})}
        values = value.get(key) if isinstance(value, Mapping) else {}
        return dict(values) if isinstance(values, Mapping) else copy.deepcopy(default)

    def _normalize_loaded(self) -> None:
        with self._lock:
            for proxy_id, row in list(self._proxies.items()):
                if not isinstance(row, Mapping):
                    self._proxies.pop(proxy_id, None)
                    continue
                row = dict(row)
                row.setdefault("proxy_id", proxy_id)
                row.setdefault("country", "ZZ")
                row.setdefault("group", "默认组")
                row.setdefault("enabled", True)
                row.setdefault("status", "unknown")
                row.setdefault("lease_owner", "")
                row.setdefault("lease_until", None)
                row.setdefault("last_checked_at", None)
                row.setdefault("last_exit_ip", "")
                row.setdefault("latency_ms", None)
                row.setdefault("consecutive_failures", 0)
                row.setdefault("quarantined_until", None)
                row.setdefault("last_failure", None)
                self._proxies[str(proxy_id)] = row

    def _save(self) -> None:
        atomic_write(self.proxies_path, {"version": 1, "proxies": self._proxies})
        atomic_write(self.subscriptions_path, {"version": 1, "subscriptions": self._subscriptions})
        atomic_write(self.config_path, self._config)

    def public_config(self) -> dict[str, Any]:
        with self._lock:
            return copy.deepcopy(self._config)

    def save_config(self, value: Mapping[str, Any]) -> dict[str, Any]:
        with self._lock:
            updated = copy.deepcopy(self._config)
            updated.update({key: value[key] for key in DEFAULT_NETWORK_CONFIG if key in value})
            try:
                updated["workers"] = max(1, min(5, int(updated.get("workers") or 3)))
                updated["connect_timeout_seconds"] = max(1, min(120, int(updated.get("connect_timeout_seconds") or 10)))
                updated["request_timeout_seconds"] = max(3, min(300, int(updated.get("request_timeout_seconds") or 30)))
            except (TypeError, ValueError) as exc:
                raise NetworkToolError("network_config", "保存网络工具配置", "超时时间和并发数必须是整数", retryable=False) from exc
            self._config = updated
            self._save()
            return self.public_config()

    def public(self) -> dict[str, Any]:
        with self._lock:
            rows = [_public(row) for row in self._proxies.values()]
        rows.sort(key=lambda row: (row.get("country") or "ZZ", row.get("group") or "", row.get("proxy_id") or ""))
        groups: dict[tuple[str, str], dict[str, Any]] = {}
        for row in rows:
            key = (str(row.get("country") or "ZZ"), str(row.get("group") or "默认组"))
            item = groups.setdefault(key, {"country": key[0], "group": key[1], "total": 0, "enabled": 0, "available": 0, "leased": 0, "quarantined": 0, "schemes": set()})
            item["total"] += 1
            item["enabled"] += int(bool(row.get("enabled")))
            item["available"] += int(row.get("enabled") and row.get("status") in {"unknown", "available"})
            item["leased"] += int(bool(row.get("lease_owner")))
            item["quarantined"] += int(row.get("status") == "quarantined")
            item["schemes"].add(row.get("scheme"))
        summaries = []
        for item in groups.values():
            item["schemes"] = sorted(value for value in item["schemes"] if value)
            summaries.append(item)
        return {"rows": rows, "groups": sorted(summaries, key=lambda item: (item["country"], item["group"])), "total": len(rows)}

    def import_text(self, content: str, *, country: str = "ZZ", group: str = "默认组", scheme: str = "http", source: str = "manual") -> dict[str, Any]:
        imported = 0
        skipped = 0
        errors: list[dict[str, Any]] = []
        normalized_country = _country(country)
        normalized_group = _text(group, 80) or "默认组"
        for index, raw in enumerate(str(content or "").splitlines(), 1):
            if not raw.strip() or raw.lstrip().startswith("#"):
                continue
            try:
                parsed = _parse_proxy(raw, default_scheme=scheme)
            except ValueError as exc:
                skipped += 1
                errors.append({"line": index, "reason": _text(exc, 180)})
                continue
            with self._lock:
                existing = dict(self._proxies.get(parsed["proxy_id"]) or {})
                # Keep health/lease metadata for an existing identity, while
                # allowing a re-import to replace the endpoint and protocol.
                # This matters when the same host/credentials are first
                # imported as HTTP and later corrected to SOCKS5/SOCKS5H.
                merged = {**existing, **parsed}
                merged.update({"country": normalized_country, "group": normalized_group, "source": source, "enabled": True})
                parsed = merged
                parsed.setdefault("status", "unknown")
                parsed.setdefault("consecutive_failures", 0)
                self._proxies[parsed["proxy_id"]] = parsed
            imported += 1
        with self._lock:
            self._save()
        return {"imported": imported, "skipped": skipped, "errors": errors, **self.public()}

    def _decode_subscription(self, content: str, *, country: str, group: str, subscription_id: str) -> list[str]:
        text = str(content or "").strip()
        if not text:
            return []
        decoded = text
        try:
            candidate = base64.b64decode("".join(text.split()), validate=False).decode("utf-8", "ignore")
            if any(prefix in candidate for prefix in ("vmess://", "vless://", "trojan://", "ss://", "http://", "https://")):
                decoded = candidate
        except Exception:
            pass
        lines: list[str] = []
        for line in decoded.splitlines():
            line = line.strip().strip("- ")
            if "://" in line and line.split(":", 1)[0].lower() in SUPPORTED_SCHEMES | {"vmess", "vless", "trojan", "ss"}:
                lines.append(line)
        if lines:
            return lines
        # Lightweight Clash YAML support without making PyYAML a runtime
        # requirement.  Credentials remain in the private proxy store only;
        # public responses contain protocol/host/port metadata.
        current: dict[str, str] = {}
        blocks: list[dict[str, str]] = []
        for raw_line in decoded.splitlines() + ["- __end__: true"]:
            stripped = raw_line.strip()
            if stripped.startswith("-"):
                if current:
                    blocks.append(current)
                    current = {}
                stripped = stripped[1:].strip()
            if ":" not in stripped or stripped.startswith(("proxies:", "proxy-groups:", "rules:")):
                continue
            key, value = stripped.split(":", 1)
            key, value = key.strip().lower(), value.strip().strip("'\"")
            if key in {"type", "server", "port", "username", "password", "name"}:
                current[key] = value
        for block in blocks:
            protocol = str(block.get("type") or "").lower()
            host = str(block.get("server") or "").strip()
            port = str(block.get("port") or "").strip()
            if not protocol or not host or not port:
                continue
            if protocol in SUPPORTED_SCHEMES:
                auth = ""
                if block.get("username"):
                    auth = quote(block["username"], safe="")
                    if block.get("password"):
                        auth += ":" + quote(block["password"], safe="")
                    auth += "@"
                lines.append(f"{protocol}://{auth}{host}:{port}")
            else:
                # Keep unsupported protocol nodes visible as metadata so the
                # UI can explain why a Mihomo-backed test is required.
                lines.append(f"{protocol}://{host}:{port}")
        return lines

    def import_subscription(self, subscription_url: str, content: str, *, country: str = "ZZ", group: str = "默认组") -> dict[str, Any]:
        subscription_id = hashlib.sha256(str(subscription_url).encode("utf-8")).hexdigest()[:16]
        lines = self._decode_subscription(content, country=_country(country), group=_text(group, 80) or "默认组", subscription_id=subscription_id)
        imported = self.import_text("\n".join(line for line in lines if line.split(":", 1)[0].lower() in SUPPORTED_SCHEMES), country=country, group=group, source="subscription")
        parsed_nodes = []
        for line in lines:
            parsed = urlsplit(line)
            scheme_name = parsed.scheme.lower()
            parsed_nodes.append({
                "scheme": scheme_name,
                "host": parsed.hostname or "",
                "port": parsed.port,
                "supported_direct": scheme_name in SUPPORTED_SCHEMES,
            })
        with self._lock:
            self._subscriptions[subscription_id] = {"subscription_id": subscription_id, "url": str(subscription_url or "").strip(), "content": str(content or ""), "country": _country(country), "group": _text(group, 80) or "默认组", "last_imported_at": int(time.time()), "node_count": len(lines), "parsed_nodes": parsed_nodes}
            self._save()
        return {"subscription_id": subscription_id, "node_count": len(lines), "parsed_nodes": parsed_nodes, "mihomo": self.mihomo_status(), **imported}

    def mihomo_status(self) -> dict[str, Any]:
        return IsolatedMihomo(str(self._config.get("mihomo_path") or "")).status()

    def test_subscription(self, subscription_id: str, *, target_url: str = "", exit_url: str = "") -> dict[str, Any]:
        with self._lock:
            subscription = self._subscriptions.get(str(subscription_id))
            if not isinstance(subscription, Mapping):
                raise NetworkToolError("network_subscription_test", "订阅节点测试", "订阅记录不存在", retryable=False)
            source = str(subscription.get("content") or "")
        runtime = IsolatedMihomo(str(self._config.get("mihomo_path") or ""))
        status = runtime.status()
        if not status["available"]:
            return {"tested": False, "available": False, "message": status["message"], "subscription_id": str(subscription_id)}
        # Keep the user's subscription in an isolated directory and override
        # only the mixed port. Existing Clash Verge configuration is untouched.
        port_probe = socket.socket()
        try:
            port_probe.bind(("127.0.0.1", 0))
            mixed_port = int(port_probe.getsockname()[1])
        finally:
            port_probe.close()
        yaml_text = source
        if "mixed-port:" in yaml_text:
            yaml_text = re.sub(r"(?m)^\s*mixed-port\s*:\s*\d+", f"mixed-port: {mixed_port}", yaml_text, count=1)
        else:
            yaml_text = f"mixed-port: {mixed_port}\nallow-lan: false\n" + yaml_text
        session = None
        try:
            runtime.start({"yaml": yaml_text})
            time.sleep(0.5)
            if getattr(runtime, "_process", None) is not None and runtime._process.poll() is not None:
                raise NetworkToolError("network_subscription_test", "订阅节点测试", "隔离 Mihomo 启动后立即退出")
            session = self._default_session()
            session.trust_env = False
            proxies = {"http": f"http://127.0.0.1:{mixed_port}", "https": f"http://127.0.0.1:{mixed_port}"}
            started = time.monotonic()
            response = session.get(target_url or self._config.get("default_target_url"), proxies=proxies, timeout=float(self._config.get("request_timeout_seconds") or 30), allow_redirects=False)
            exit_response = session.get(exit_url or self._config.get("default_exit_url"), proxies=proxies, timeout=float(self._config.get("request_timeout_seconds") or 30), allow_redirects=False)
            try:
                payload = exit_response.json()
                exit_ip = _text(payload.get("ip") if isinstance(payload, Mapping) else payload, 80)
            except Exception:
                exit_ip = _text(getattr(exit_response, "text", ""), 80)
            return {"tested": True, "available": True, "subscription_id": str(subscription_id), "http_status": int(getattr(response, "status_code", 0) or 0), "exit_ip": exit_ip, "proxy_to_target_ms": round((time.monotonic() - started) * 1000, 1)}
        except NetworkToolError:
            raise
        except Exception as exc:
            raise NetworkToolError("network_subscription_test", "订阅节点测试", f"隔离 Mihomo 节点测试失败：{_safe_failure(exc)}") from exc
        finally:
            if session is not None:
                try:
                    session.close()
                except Exception:
                    pass
            runtime.stop()

    def _get(self, proxy_id: str) -> dict[str, Any]:
        with self._lock:
            row = self._proxies.get(str(proxy_id))
            if not isinstance(row, Mapping):
                raise NetworkToolError("network_proxy_select", "选择网络代理", "代理不存在", retryable=False)
            if not row.get("enabled"):
                raise NetworkToolError("network_proxy_select", "选择网络代理", "代理已停用", retryable=False)
            return dict(row)

    def test(self, proxy_id: str, *, mode: str = "quick", target_url: str = "", exit_url: str = "") -> dict[str, Any]:
        row = self._get(proxy_id)
        if mode not in {"quick", "deep"}:
            raise NetworkToolError("network_test", "代理测活", "测活模式必须是 quick 或 deep", retryable=False)
        timeout = float(self._config.get("connect_timeout_seconds") or 10)
        started = time.monotonic()
        result: dict[str, Any] = {"proxy_id": row["proxy_id"], "scheme": row["scheme"], "masked": mask_proxy(_proxy_url(row)), "mode": mode, "local_to_proxy_ms": None, "proxy_to_target_ms": None, "exit_ip": "", "http_status": None}
        try:
            sock = self._socket_factory((row["host"], int(row["port"])), timeout=timeout)
            result["local_to_proxy_ms"] = round((time.monotonic() - started) * 1000, 1)
            try:
                sock.close()
            except Exception:
                pass
            if mode == "deep":
                session = self._session_factory() if self._session_factory else self._default_session()
                try:
                    session.trust_env = False
                    proxies = {"http": _proxy_url(row), "https": _proxy_url(row)}
                    response = session.get(target_url or self._config.get("default_target_url"), proxies=proxies, timeout=float(self._config.get("request_timeout_seconds") or 30), allow_redirects=False)
                    result["proxy_to_target_ms"] = round((time.monotonic() - started) * 1000, 1)
                    result["http_status"] = int(getattr(response, "status_code", 0) or 0)
                    exit_response = session.get(exit_url or self._config.get("default_exit_url"), proxies=proxies, timeout=float(self._config.get("request_timeout_seconds") or 30), allow_redirects=False)
                    try:
                        payload = exit_response.json()
                        result["exit_ip"] = _text(payload.get("ip") if isinstance(payload, Mapping) else payload, 80)
                    except Exception:
                        result["exit_ip"] = _text(getattr(exit_response, "text", ""), 80)
                finally:
                    try:
                        session.close()
                    except Exception:
                        pass
            result["ok"] = True
            with self._lock:
                current = self._proxies[row["proxy_id"]]
                current.update({"status": "available", "last_checked_at": int(time.time()), "last_exit_ip": result["exit_ip"], "latency_ms": result["proxy_to_target_ms"] or result["local_to_proxy_ms"], "consecutive_failures": 0, "last_failure": None})
                self._save()
            return result
        except Exception as exc:
            result.update({"ok": False, "error": _safe_failure(exc)})
            with self._lock:
                current = self._proxies[row["proxy_id"]]
                failures = int(current.get("consecutive_failures") or 0) + 1
                current.update({"status": "quarantined" if failures >= 2 else "unknown", "consecutive_failures": failures, "last_checked_at": int(time.time()), "last_failure": _safe_failure(exc)})
                self._save()
            raise NetworkToolError("network_test", "代理测活", f"{row['scheme']} 代理测试失败：{_safe_failure(exc)}") from exc

    @staticmethod
    def _default_session() -> Any:
        try:
            from curl_cffi import requests
            session = requests.Session(impersonate="chrome", verify=True)
        except Exception:
            import requests
            session = requests.Session()
        session.trust_env = False
        return session

    def update_group(self, *, country: str, group: str, action: str, new_group: str = "", enabled: bool | None = None) -> dict[str, Any]:
        country, group = _country(country), _text(group, 80)
        with self._lock:
            matches = [row for row in self._proxies.values() if row.get("country") == country and row.get("group") == group]
            if action == "delete":
                if any(row.get("lease_owner") for row in matches):
                    raise NetworkToolError("network_group_delete", "删除代理分组", "分组中有正在租用的代理，不能删除", retryable=False)
                for row in matches:
                    self._proxies.pop(str(row.get("proxy_id")), None)
            elif action in {"rename", "move", "enable", "disable"}:
                destination = _text(new_group, 80) or group
                for row in matches:
                    if action in {"rename", "move"}:
                        row["group"] = destination
                    if action in {"enable", "disable"}:
                        row["enabled"] = action == "enable" if enabled is None else bool(enabled)
            else:
                raise NetworkToolError("network_group", "修改代理分组", "不支持的分组操作", retryable=False)
            self._save()
        return self.public()


__all__ = ["DEFAULT_NETWORK_CONFIG", "NetworkToolError", "NetworkToolsService", "SUPPORTED_SCHEMES"]
