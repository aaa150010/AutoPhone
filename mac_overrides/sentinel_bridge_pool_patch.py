"""Resident Sentinel pool patch for the recovered Node bridge.

``codex_node_bridge`` is a recovered module loaded from ``business_pyc``; the
maintainable change lives here.  ``apply_sentinel_pool_patch`` wraps the
cached module's ``run_node_bridge`` so ``mode="real"`` calls try the resident
worker pool first and fall back to the recovered one-shot subprocess path on
any pool failure.  Token generation logic, signatures, and return structures
stay exactly those of the recovered bridge.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Dict

try:
    from sentinel_worker_pool import sentinel_worker_pool, shutdown_sentinel_worker_pools
except ImportError:  # pragma: no cover - direct module loading compatibility
    try:
        from .sentinel_worker_pool import (  # type: ignore[no-redef]
            sentinel_worker_pool,
            shutdown_sentinel_worker_pools,
        )
    except ImportError:
        # The pool module lives in engine/node_chain; a recovery install
        # without that directory keeps the one-shot bridge path.
        try:
            _POOL_DIR = Path(__file__).resolve().parent.parent / "engine" / "node_chain"
            sys.path.insert(0, str(_POOL_DIR))
            from sentinel_worker_pool import (  # type: ignore[no-redef]
                sentinel_worker_pool,
                shutdown_sentinel_worker_pools,
            )
        except ImportError:
            sentinel_worker_pool = None
            shutdown_sentinel_worker_pools = None

_PATCHED_MODULES: set[int] = set()
_BRIDGE_SOURCE_DIR = Path(__file__).resolve().parent.parent / "engine" / "node_chain"



try:
    from .quiet_note import note_stderr
except ImportError:  # pragma: no cover - top-level recovery import
    from quiet_note import note_stderr  # type: ignore[no-redef]

def _note_stderr(where: str, exc: BaseException) -> None:
    note_stderr('sentinel_bridge_pool_patch', where, exc)


def _resolve_worker_script(script_path: str) -> Path:
    """Prefer the resident worker next to the configured runner."""
    runner = Path(str(script_path or "")).resolve()
    sibling = runner.parent / "sentinel_worker.js"
    if sibling.exists():
        return sibling
    return _BRIDGE_SOURCE_DIR / "sentinel_worker.js"


def _ensure_python_helper_env() -> None:
    """Expose the host interpreter to resident pool workers.

    Pool workers copy ``os.environ`` at spawn time.  Without ``PYTHON`` /
    ``CODEX_PYTHON`` the worker falls back to plain ``python``/``py`` lookups,
    which do not exist on a macOS service PATH, and every ``real`` Sentinel
    request fails with spawnSync ENOENT.  Mirror the recovered one-shot bridge
    path, including the packaged-helper contract.
    """
    if not os.path.exists(sys.executable):
        return
    os.environ.setdefault("PYTHON", sys.executable)
    os.environ.setdefault("CODEX_PYTHON", sys.executable)
    helper_exe = getattr(sys, "frozen", False) or Path(sys.executable).stem.lower().startswith("plusbindtool")
    if helper_exe:
        os.environ.setdefault("CODEX_SENTINEL_PY_ARGS_PREFIX_JSON", json.dumps(["--sentinel-http"]))


def _run_via_pool(bridge_module: Any, args: tuple, kwargs: Dict[str, Any]) -> dict[str, Any] | None:
    """Attempt one Sentinel request through the resident pool.

    Returns ``None`` when the pool cannot serve (worker lost, timeout, bridge
    configuration mismatch); the caller then replays into the recovered
    one-shot path unchanged.
    """
    if sentinel_worker_pool is None:
        return None
    _ensure_python_helper_env()
    bridge_dir = getattr(bridge_module, "__file__", "") or ""
    node = getattr(bridge_module, "_node_binary", None)
    if not callable(node):
        return None
    node_binary = node()
    if not node_binary:
        return None
    script_path = str(kwargs.get("script_path") or "")
    worker_script = _resolve_worker_script(script_path)
    if not worker_script.exists():
        return None
    mode = str(kwargs.get("mode") or (args[0] if args else "") or "").lower()
    if mode != "real":
        return None
    try:
        pool = sentinel_worker_pool(node_binary, worker_script)
        payload = _bridge_payload(bridge_module, args, kwargs)
        if payload is None:
            return None
        timeout = max(5, int(kwargs.get("timeout") or 10))
        return pool.request(payload, timeout=max(timeout + 15, timeout * 2))
    except Exception:
        # Pool errors must degrade to the recovered path, never alter the
        # token contract.
        return None


def _bridge_payload(bridge_module: Any, args: tuple, kwargs: Dict[str, Any]) -> dict[str, Any] | None:
    """Rebuild the bridge's real-mode payload from the call arguments."""
    defaults = {
        "mode": "",
        "flow": "",
        "persona": "",
        "device_id": "",
        "proxy_label": "",
        "proxy": "",
        "script_path": "",
        "context": None,
        "timeout": 10,
    }
    call = dict(defaults)
    call.update(kwargs)
    # run_node_bridge(mode, *, flow, persona, device_id, proxy_label, proxy,
    #                  script_path, context, timeout) — mode may be positional.
    payload_keys = ("flow", "persona", "device_id", "proxy_label", "proxy", "context", "timeout")
    positional = [value for value in args if not isinstance(value, dict)]
    if positional and call["mode"] == "":
        call["mode"] = str(positional[0])
    fingerprint = kwargs.get("fingerprint")
    if fingerprint is None:
        for value in args:
            if isinstance(value, dict) and "mode" not in value:
                fingerprint = value
                break
    if not call["flow"]:
        return None
    version = getattr(bridge_module, "BRIDGE_VERSION", "node-bridge-v2")
    payload: Dict[str, Any] = {
        "mode": "real",
        "version": version,
        "flow": str(call["flow"] or ""),
        "persona": str(call["persona"] or ""),
        "device_id": str(call["device_id"] or ""),
        "proxy_label": str(call["proxy_label"] or ""),
        "proxy": str(call["proxy"] or ""),
        "fingerprint": fingerprint if isinstance(fingerprint, dict) else {},
        "context": call["context"] if isinstance(call["context"], dict) else {},
        "timeout_ms": int(max(5, (call["timeout"] or 10)) * 1000),
    }
    return payload


def _patched_run_node_bridge(bridge_module: Any, original: Any, args: tuple, kwargs: Dict[str, Any]) -> dict[str, Any]:
    pool_result = _run_via_pool(bridge_module, args, kwargs)
    if pool_result is not None and str(pool_result.get("id") or ""):
        pool_result.pop("id", None)
        token = str(
            pool_result.get("token")
            or pool_result.get("sentinel_token")
            or (pool_result.get("headers") or {}).get("OpenAI-Sentinel-Token")
            or ""
        )
        so_token = str(
            pool_result.get("so_token")
            or pool_result.get("sentinel_so_token")
            or (pool_result.get("headers") or {}).get("OpenAI-Sentinel-SO-Token")
            or ""
        )
        version = str(pool_result.get("version") or getattr(bridge_module, "BRIDGE_VERSION", "node-bridge-v2"))
        flow = str(pool_result.get("flow") or kwargs.get("flow") or "")
        pool_result.update({
            "ok": bool(pool_result.get("ok", True) and token),
            "mode": "real",
            "version": version,
            "flow": flow,
            "token": token,
            "so_token": so_token,
            "token_generated": bool(token),
        })
        if not token:
            pool_result.setdefault("error", "Node SentinelRunner returned no token")
        return pool_result
    return original(*args, **kwargs)


def apply_sentinel_pool_patch(bridge_module: Any) -> bool:
    """Wrap the cached bridge module's ``run_node_bridge`` with the pool.

    Idempotent: repeated calls on the same module object are no-ops.
    """
    # Set the helper env on the host process once, before any resident pool
    # (this patch's or the recovered bridge's internal one) copies os.environ
    # to spawn workers.
    _ensure_python_helper_env()
    module_id = id(bridge_module)
    if module_id in _PATCHED_MODULES:
        return True
    original = getattr(bridge_module, "run_node_bridge", None)
    if not callable(original):
        return False
    if getattr(original, "_sentinel_pool_patched", False):
        _PATCHED_MODULES.add(module_id)
        return True

    def run_node_bridge(*args: Any, **kwargs: Any) -> dict[str, Any]:
        return _patched_run_node_bridge(bridge_module, original, args, kwargs)

    run_node_bridge._sentinel_pool_patched = True  # type: ignore[attr-defined]
    run_node_bridge.__wrapped_original__ = original  # type: ignore[attr-defined]
    bridge_module.run_node_bridge = run_node_bridge
    _PATCHED_MODULES.add(module_id)
    return True


def register_exit_cleanup() -> None:
    if callable(shutdown_sentinel_worker_pools):
        try:
            import atexit

            atexit.register(shutdown_sentinel_worker_pools)
        except Exception as exc:
            _note_stderr("L208", exc)


__all__ = ["apply_sentinel_pool_patch", "register_exit_cleanup"]
