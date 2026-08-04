"""Resolve the Node.js executable used by the recovered Sentinel bridge."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
from typing import MutableMapping


def _executable_path(value: str, *, which=shutil.which) -> str | None:
    candidate = str(value or "").strip()
    if not candidate:
        return None
    if os.sep not in candidate:
        resolved = which(candidate)
        return resolved if resolved and os.access(resolved, os.X_OK) else None
    path = Path(candidate).expanduser()
    if path.is_file() and os.access(path, os.X_OK):
        return str(path.resolve())
    return None


def configure_node_runtime(
    environ: MutableMapping[str, str] | None = None,
    *,
    which=shutil.which,
) -> str | None:
    """Set a verified Node path and prepend its directory to PATH.

    An invalid inherited ``CODEX_NODE_BINARY`` is discarded instead of being
    allowed to mask an otherwise usable ``node`` found on PATH.
    """

    env = environ if environ is not None else os.environ
    explicit = str(env.get("CODEX_NODE_BINARY") or "").strip()
    node_binary = _executable_path(explicit, which=which) if explicit else None
    if node_binary is None:
        node_binary = _executable_path(str(which("node") or ""), which=which)

    if node_binary is None:
        env.pop("CODEX_NODE_BINARY", None)
        return None

    env["CODEX_NODE_BINARY"] = node_binary
    node_dir = str(Path(node_binary).parent)
    path_parts = [item for item in str(env.get("PATH") or "").split(os.pathsep) if item]
    if node_dir not in path_parts:
        env["PATH"] = os.pathsep.join([node_dir, *path_parts])
    return node_binary
