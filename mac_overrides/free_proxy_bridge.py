"""Local HTTP CONNECT bridge for browser drivers that reject SOCKS5 auth."""

from __future__ import annotations

from http import HTTPStatus
import select
import socket
import socketserver
import threading
import time
from typing import Any
from urllib.parse import unquote, urlsplit

try:
    from .free_register_common import normalize_proxy_value
except ImportError:
    from free_register_common import normalize_proxy_value  # type: ignore[no-redef]


_BUFFER_SIZE = 64 * 1024
_HEADER_LIMIT = 64 * 1024
_SOCKET_TIMEOUT = 20.0


def _authority(value: str, default_port: int) -> tuple[str, int] | None:
    text = str(value or "").strip()
    if not text:
        return None
    if text.startswith("["):
        end = text.find("]")
        if end < 0:
            return None
        host = text[1:end]
        port_text = text[end + 1:].lstrip(":")
    elif ":" in text:
        host, port_text = text.rsplit(":", 1)
    else:
        host, port_text = text, str(default_port)
    try:
        port = int(port_text or default_port)
    except (TypeError, ValueError):
        return None
    if not host or not 1 <= port <= 65535:
        return None
    return host, port


class _SocksHttpHandler(socketserver.BaseRequestHandler):
    bridge: "Socks5HttpBridge"

    def handle(self) -> None:
        client = self.request
        client.settimeout(_SOCKET_TIMEOUT)
        upstream: Any = None
        started = time.monotonic()
        try:
            head, remainder = self._read_headers(client)
            if not head:
                return
            lines = head.split(b"\r\n")
            method, target, version = self._request_line(lines[0].decode("latin-1", "replace"))
            if not method or not target:
                self._reply(client, HTTPStatus.BAD_REQUEST)
                return
            connect_mode = method.upper() == "CONNECT"
            if connect_mode:
                destination = _authority(target, 443)
                if destination is None:
                    self._reply(client, HTTPStatus.BAD_REQUEST)
                    return
            else:
                parsed = urlsplit(target)
                if parsed.scheme and parsed.hostname:
                    destination = (parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80))
                    path = parsed.path or "/"
                    if parsed.query:
                        path += "?" + parsed.query
                    lines[0] = f"{method} {path} {version}".encode("latin-1", "replace")
                else:
                    host_header = next(
                        (
                            line.split(b":", 1)[1].strip().decode("latin-1", "replace")
                            for line in lines[1:]
                            if line.lower().startswith(b"host:") and b":" in line
                        ),
                        "",
                    )
                    destination = _authority(host_header, 80)
                    if destination is None:
                        self._reply(client, HTTPStatus.BAD_REQUEST)
                        return
                lines = [line for line in lines if line.lower() != b"proxy-connection: keep-alive"]
                head = b"\r\n".join(lines)
            upstream = self.bridge._connect_upstream(*destination)
            self.bridge._record_event("connect_established", elapsed_ms=int((time.monotonic() - started) * 1000))
            if connect_mode:
                client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                self._relay(client, upstream)
            else:
                upstream.sendall(head + b"\r\n\r\n" + remainder)
                self._relay(client, upstream)
        except (OSError, ValueError, RuntimeError) as exc:
            self.bridge._record_event("request_failed", reason=type(exc).__name__, elapsed_ms=int((time.monotonic() - started) * 1000))
            try:
                self._reply(client, HTTPStatus.BAD_GATEWAY)
            except OSError:
                pass
        finally:
            self.bridge._record_event("closed", reason="request_complete", elapsed_ms=int((time.monotonic() - started) * 1000))
            for connection in (upstream, client):
                try:
                    if connection is not None:
                        connection.close()
                except OSError:
                    pass

    @staticmethod
    def _request_line(value: str) -> tuple[str, str, str]:
        parts = value.split()
        return (parts[0], parts[1], parts[2]) if len(parts) == 3 else ("", "", "")

    @staticmethod
    def _read_headers(client: socket.socket) -> tuple[bytes, bytes]:
        data = bytearray()
        while len(data) < _HEADER_LIMIT:
            chunk = client.recv(4096)
            if not chunk:
                break
            data.extend(chunk)
            marker = data.find(b"\r\n\r\n")
            if marker >= 0:
                end = marker + 4
                return bytes(data[:marker]), bytes(data[end:])
        return b"", b""

    @staticmethod
    def _reply(client: socket.socket, status: HTTPStatus) -> None:
        client.sendall(f"HTTP/1.1 {int(status)} {status.phrase}\r\nConnection: close\r\n\r\n".encode("ascii"))

    def _relay(self, left: socket.socket, right: socket.socket) -> None:
        sockets = [left, right]
        while True:
            readable, _, exceptional = select.select(sockets, [], sockets, _SOCKET_TIMEOUT)
            if exceptional:
                self.bridge._record_event("relay_error", reason="socket_exception")
                return
            if not readable:
                with self.bridge._metrics_lock:
                    self.bridge._metrics["relay_timeouts"] += 1
                    self.bridge._metrics.update({
                        "last_event": "relay_timeout",
                        "last_reason": "idle_timeout",
                        "last_elapsed_ms": int(_SOCKET_TIMEOUT * 1000),
                    })
                return
            for source in readable:
                data = source.recv(_BUFFER_SIZE)
                if not data:
                    return
                (right if source is left else left).sendall(data)


class Socks5HttpBridge:
    """Expose one authenticated SOCKS5 proxy as a loopback HTTP proxy."""

    def __init__(self, proxy: str) -> None:
        normalized = normalize_proxy_value(proxy)
        parsed = urlsplit(normalized)
        scheme = parsed.scheme.lower()
        if scheme not in {"socks5", "socks5h"} or not parsed.hostname or not parsed.port:
            raise ValueError("仅支持带认证的 SOCKS5 代理桥接")
        self.upstream_host = str(parsed.hostname)
        self.upstream_port = int(parsed.port)
        self.username = unquote(str(parsed.username or ""))
        self.password = unquote(str(parsed.password or ""))
        if not self.username or not self.password:
            raise ValueError("SOCKS5 代理桥接缺少认证")
        handler = type("_BoundSocksHttpHandler", (_SocksHttpHandler,), {"bridge": self})
        self._server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), handler)
        self._server.daemon_threads = True
        self._server.allow_reuse_address = True
        self._thread = threading.Thread(target=self._server.serve_forever, name="gptphone-socks-bridge", daemon=True)
        self._closed = False
        self._metrics_lock = threading.Lock()
        self._metrics = {
            "created_at": time.time(),
            "connect_attempts": 0,
            "connect_successes": 0,
            "connect_failures": 0,
            "relay_timeouts": 0,
            "close_count": 0,
            "last_event": "created",
            "last_reason": "",
            "last_elapsed_ms": None,
        }
        self._thread.start()

    @property
    def proxy_config(self) -> dict[str, str]:
        host, port = self._server.server_address[:2]
        return {"server": f"http://{host}:{port}"}

    def _connect_upstream(self, host: str, port: int) -> socket.socket:
        try:
            import socks
        except ImportError as exc:  # pragma: no cover - start.command installs PySocks
            raise RuntimeError("PySocks is required for the browser proxy bridge") from exc
        started = time.monotonic()
        with self._metrics_lock:
            self._metrics["connect_attempts"] += 1
        connection = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
        connection.settimeout(_SOCKET_TIMEOUT)
        connection.set_proxy(
            socks.SOCKS5,
            self.upstream_host,
            self.upstream_port,
            rdns=True,
            username=self.username,
            password=self.password,
        )
        try:
            connection.connect((host, int(port)))
        except Exception as exc:
            with self._metrics_lock:
                self._metrics["connect_failures"] += 1
                self._metrics.update({"last_event": "connect_failed", "last_reason": type(exc).__name__, "last_elapsed_ms": int((time.monotonic() - started) * 1000)})
            raise
        with self._metrics_lock:
            self._metrics["connect_successes"] += 1
            self._metrics.update({"last_event": "connect_established", "last_reason": "", "last_elapsed_ms": int((time.monotonic() - started) * 1000)})
        return connection

    def _record_event(self, event: str, *, reason: str = "", elapsed_ms: int | None = None) -> None:
        with self._metrics_lock:
            self._metrics["last_event"] = str(event or "")[:40]
            self._metrics["last_reason"] = str(reason or "")[:80]
            if elapsed_ms is not None:
                self._metrics["last_elapsed_ms"] = max(0, int(elapsed_ms))

    def diagnostics(self) -> dict[str, Any]:
        """Return non-secret bridge counters for structured diagnostics."""
        with self._metrics_lock:
            return dict(self._metrics)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._record_event("close_requested", reason="explicit")
        with self._metrics_lock:
            self._metrics["close_count"] += 1
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=2.0)


__all__ = ["Socks5HttpBridge"]
