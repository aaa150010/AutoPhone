"""Credential-tunnel sticky-session template and pool target-size maintenance.

The tunnel template turns one provider credential (gateway host:port, base
username with ``{sid}``/``{t}`` placeholders, password) into self-rotating
sticky-session proxy rows.  Every minted row carries the reserved
``source_label`` ``tunnel-auto``: only those rows may be deleted
programmatically, manually imported rows are never rewritten.

``ensure_target`` keeps the dispatchable pool at the configured size: it
counts every eligible row (manual or tunnel) toward the target, deletes
burned tunnel rows first, and mints fresh sids for the deficit bounded by a
2x capacity cap so rows quarantined-but-recovering cannot grow the pool
without bound.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping
from urllib.parse import quote
import secrets
import string
import time

try:
    from .free_proxy_parse import _parse
    from .free_register_common import FreeRegisterError
except ImportError:  # macOS launcher imports overrides as top-level modules.
    from free_proxy_parse import _parse  # type: ignore[no-redef]
    from free_register_common import FreeRegisterError  # type: ignore[no-redef]


TUNNEL_SOURCE_LABEL = "tunnel-auto"
_SID_ALPHABET = string.ascii_letters + string.digits
_SID_LENGTH = 10
_REQUIRED_PLACEHOLDER = "{sid}"
_TARGET_CAPACITY_MULTIPLIER = 2


@dataclass(frozen=True, slots=True)
class TunnelTemplate:
    """Validated credential-tunnel template for minting sticky-session rows."""

    gateway_host: str
    gateway_port: int
    scheme: str
    username_template: str
    password: str
    sticky_minutes: int

    def render_username(self, *, sid: str, sticky_minutes: int | None = None) -> str:
        minutes = int(self.sticky_minutes if sticky_minutes is None else sticky_minutes)
        return self.username_template.format(sid=str(sid), t=minutes)

    def mint_proxy(self, *, sticky_minutes: int | None = None) -> str:
        """Render one fresh proxy URL with a new random session id."""
        sid = "".join(secrets.choice(_SID_ALPHABET) for _ in range(_SID_LENGTH))
        username = self.render_username(sid=sid, sticky_minutes=sticky_minutes)
        return (
            f"{self.scheme}://{quote(username, safe='')}"
            f":{quote(self.password, safe='')}@{self.gateway_host}:{self.gateway_port}"
        )


def template_from_config(config: Mapping[str, Any]) -> TunnelTemplate | None:
    """Build a validated template from normalized Free config.

    Returns None when the tunnel is disabled, incomplete, or the template is
    malformed; every downstream caller then stays a no-op.
    """
    if not bool(config.get("proxy_tunnel_enabled")):
        return None
    username_template = str(config.get("proxy_tunnel_username_template") or "").strip()
    gateway_host = str(config.get("proxy_tunnel_gateway_host") or "").strip().lower()
    try:
        gateway_port = int(config.get("proxy_tunnel_gateway_port") or 0)
    except (TypeError, ValueError):
        return None
    if not username_template or _REQUIRED_PLACEHOLDER not in username_template:
        return None
    if not gateway_host or not 1 <= gateway_port <= 65535:
        return None
    try:
        username_template.format(sid="", t=0)
    except (KeyError, IndexError, ValueError):
        return None
    try:
        sticky_minutes = int(config.get("proxy_tunnel_sticky_minutes") or 30)
    except (TypeError, ValueError):
        sticky_minutes = 30
    return TunnelTemplate(
        gateway_host=gateway_host,
        gateway_port=gateway_port,
        scheme=str(config.get("proxy_tunnel_scheme") or "socks5").strip().lower(),
        username_template=username_template,
        password=str(config.get("proxy_tunnel_password") or ""),
        sticky_minutes=max(5, min(120, sticky_minutes)),
    )


def resolve_target_size(config: Mapping[str, Any]) -> int:
    """Return the configured pool target, falling back to ``concurrency``."""
    try:
        explicit = int(config.get("proxy_pool_target_size") or 0)
    except (TypeError, ValueError):
        explicit = 0
    if explicit > 0:
        return max(1, min(16, explicit))
    try:
        concurrency = int(config.get("concurrency") or 0)
    except (TypeError, ValueError):
        concurrency = 0
    return max(0, min(16, concurrency))


def _tunnel_rows(pool: Any) -> list[Mapping[str, Any]]:
    entries = pool.entries() if callable(getattr(pool, "entries", None)) else []
    return [
        row for row in entries
        if isinstance(row, Mapping)
        and str(row.get("source_label") or "") == TUNNEL_SOURCE_LABEL
    ]


def _row_id_for_line(pool: Any, line: str, scheme: str) -> str:
    parsed = _parse(line, scheme)
    if parsed is None:
        return ""
    normalized = str(parsed[0])
    for row in pool.entries():
        if str(row.get("_normalized") or "") == normalized:
            return str(row.get("proxy_id") or "")
    return ""


def ensure_target(pool: Any, template: TunnelTemplate | None, *, target: int, now: float | None = None) -> int:
    """Mint tunnel rows until the dispatchable pool reaches ``target``.

    Every eligible row counts toward the target; burned tunnel-auto rows are
    deleted first so a replacement never accumulates behind a dead exit, and
    the mint is capped at ``2 * target`` total tunnel rows.  Returns the
    number of rows minted.
    """
    if template is None or int(target or 0) <= 0:
        return 0
    target = int(target)
    for row in _tunnel_rows(pool):
        if str(row.get("status") or "") == "burned":
            pool.remove(str(row.get("proxy_id") or ""))
    deficit = target - int(pool.healthy_count(driver="protocol"))
    if deficit <= 0:
        return 0
    capacity = max(0, _TARGET_CAPACITY_MULTIPLIER * target - len(_tunnel_rows(pool)))
    minted = 0
    current_time = time.time() if now is None else float(now)
    for _ in range(min(deficit, capacity)):
        line = template.mint_proxy()
        try:
            if not pool.import_text(line + "\n", source_label=TUNNEL_SOURCE_LABEL):
                break
        except FreeRegisterError:
            break
        proxy_id = _row_id_for_line(pool, line, template.scheme)
        if proxy_id:
            pool.annotate_window(
                proxy_id,
                started_at=current_time,
                expires_at=current_time + template.sticky_minutes * 60,
            )
        minted += 1
    return minted


__all__ = [
    "TUNNEL_SOURCE_LABEL",
    "TunnelTemplate",
    "ensure_target",
    "resolve_target_size",
    "template_from_config",
]
