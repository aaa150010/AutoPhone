"""Private mailbox, proxy, result and task stores for Free registration."""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import re
import threading
import time
from typing import Any, Callable, Mapping, Sequence

try:
    from .free_failure_runtime import canonical_failure, sanitize_failure_text
    from .free_register_common import (
        DEFAULT_FREE_PROXY_SCHEME,
        FREE_PROXY_SCHEMES,
        FreeMailbox,
        FreeRegisterError,
        ProxyBinding,
        atomic_write,
        fingerprint,
        mask_proxy,
        normalize_proxy_value,
        parse_mailbox_line,
        proxy_error_detail,
    )
    from .free_proxy_store import FreeProxyPool as StructuredFreeProxyPool
except ImportError:
    from free_failure_runtime import (  # type: ignore[no-redef]
        canonical_failure,
        sanitize_failure_text,
    )
    from free_register_common import (  # type: ignore[no-redef]
        DEFAULT_FREE_PROXY_SCHEME,
        FREE_PROXY_SCHEMES,
        FreeMailbox,
        FreeRegisterError,
        ProxyBinding,
        atomic_write,
        fingerprint,
        mask_proxy,
        normalize_proxy_value,
        parse_mailbox_line,
        proxy_error_detail,
    )
    from free_proxy_store import FreeProxyPool as StructuredFreeProxyPool  # type: ignore[no-redef]


ACTIVE_POOL_STATUSES = frozenset({"reserved", "queued", "running"})
FREE_EMAIL_429_COOLDOWN_SECONDS = 300


def _cooldown_timestamp(value: Any) -> float:
    try:
        return max(0.0, float(value or 0))
    except (TypeError, ValueError):
        return 0.0


class FreeMailboxPool:
    def __init__(self, data_dir: str | Path) -> None:
        self.data_dir = Path(data_dir).expanduser().resolve()
        self.pool_path = self.data_dir / "free_mailbox_pool.txt"
        self.state_path = self.data_dir / "free_mailbox_state.json"
        self.results_dir = self.data_dir / "free_register_results"
        self._lock = threading.RLock()

    def _state(self) -> dict[str, Any]:
        try:
            value = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError):
            value = {}
        rows = value.get("rows") if isinstance(value, dict) else {}
        return {"version": 2, "rows": rows if isinstance(rows, dict) else {}}

    def import_text(self, content: str) -> int:
        added, _skipped = self.import_text_with_stats(content)
        return added

    def import_text_with_stats(self, content: str) -> tuple[int, int]:
        incoming = self._parse_content(content)
        if not incoming:
            raise FreeRegisterError("free_pool", "Free 邮箱池", "Free 邮箱池没有有效的邮箱-取码 URL")
        with self._lock:
            existing = self.entries()
            existing_ids = {entry.row_id for entry in existing}
            combined: list[FreeMailbox] = []
            seen: set[str] = set()
            for entry in [*existing, *incoming]:
                if entry.row_id not in seen:
                    seen.add(entry.row_id)
                    combined.append(entry)
            added = sum(entry.row_id not in existing_ids for entry in incoming)
            self._write_entries(combined)
            state = self._state()
            for entry in combined:
                state["rows"].setdefault(
                    entry.row_id,
                    {"email": entry.email, "mailbox_url": entry.mailbox_url, "status": "available"},
                )
            atomic_write(self.state_path, state)
        return added, max(0, len(incoming) - added)

    def _write_entries(self, entries: Sequence[FreeMailbox]) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.pool_path.write_text(
            "".join(f"{entry.email}----{entry.mailbox_url}\n" for entry in entries),
            encoding="utf-8",
        )
        os.chmod(self.pool_path, 0o600)

    def _parse_content(self, content: str) -> list[FreeMailbox]:
        entries: list[FreeMailbox] = []
        seen: set[str] = set()
        for line_no, raw in enumerate(str(content or "").splitlines(), 1):
            parsed = parse_mailbox_line(raw)
            if parsed is None:
                continue
            email, mailbox_url = parsed
            row_id = fingerprint(f"{email}|{mailbox_url}")
            if row_id in seen:
                continue
            seen.add(row_id)
            entries.append(FreeMailbox(row_id, line_no, email, mailbox_url))
        return entries

    def entries(self) -> list[FreeMailbox]:
        try:
            return self._parse_content(self.pool_path.read_text(encoding="utf-8"))
        except (FileNotFoundError, OSError, UnicodeError):
            return []

    def _row_state(self, row_id: str) -> dict[str, Any]:
        return self._state()["rows"].get(row_id, {})

    def entry(self, row_id: str) -> FreeMailbox | None:
        target = str(row_id or "").strip().lower()
        return next((row for row in self.entries() if row.row_id == target), None)

    def available(self, count: int) -> list[FreeMailbox]:
        with self._lock:
            state = self._state()["rows"]
            now = time.time()
            return [
                row for row in self.entries()
                if str(state.get(row.row_id, {}).get("status") or "available") == "available"
                and _cooldown_timestamp(state.get(row.row_id, {}).get("cooldown_until")) <= now
            ][:max(0, int(count))]

    def reserve(self, rows: Sequence[FreeMailbox], batch_id: str) -> None:
        with self._lock:
            state = self._state()
            for row in rows:
                current = state["rows"].setdefault(row.row_id, {})
                if current.get("status") not in (None, "available") or _cooldown_timestamp(current.get("cooldown_until")) > time.time():
                    raise FreeRegisterError(
                        "free_pool_reserve", "预留 Free 邮箱", "Free 邮箱已被其他任务预留"
                    )
                current.update({
                    "email": row.email,
                    "mailbox_url": row.mailbox_url,
                    "status": "reserved",
                    "batch_id": batch_id,
                    "error": "",
                })
                current.pop("failure", None)
            atomic_write(self.state_path, state)

    def update(self, row_id: str, **values: Any) -> None:
        with self._lock:
            state = self._state()
            row = state["rows"].setdefault(str(row_id), {})
            updates = {key: value for key, value in values.items() if value is not None}
            if "failure" in values:
                failure = canonical_failure(values.get("failure"))
                if failure is None:
                    row.pop("failure", None)
                else:
                    updates["failure"] = failure
            row.update(updates)
            atomic_write(self.state_path, state)

    def recover_reserved(self) -> int:
        """Release rows reserved before a process could create their tasks."""
        with self._lock:
            state = self._state()
            changed = 0
            for row in state["rows"].values():
                if not isinstance(row, Mapping) or row.get("status") != "reserved":
                    continue
                row.update({"status": "available", "batch_id": "", "stage": ""})
                row.pop("cooldown_until", None)
                changed += 1
            if changed:
                atomic_write(self.state_path, state)
            return changed

    def recover_interrupted(self, row_id: str, *, reusable: bool, failure: Mapping[str, Any] | None = None) -> None:
        """Persist a deterministic state for a task interrupted by restart."""
        with self._lock:
            state = self._state()
            row = state["rows"].setdefault(str(row_id), {})
            normalized = canonical_failure(failure)
            if reusable:
                row.update({
                    "status": "available", "batch_id": "", "stage": "", "error": "",
                    "driver": "", "proxy": "", "proxy_masked": "", "proxy_fingerprint": "",
                    "proxy_id": "", "proxy_scheme": "", "proxy_country": "", "proxy_group": "",
                    "expected_exit_ip": "", "registration_ip": "", "exit_ip": "",
                })
                if normalized is not None:
                    row.update({"error": normalized["public_message"], "failure": normalized})
            else:
                row.update({"status": "failed", "stage": "free_process_recovery", "error": "Free 进程重启，中断任务未完成"})
                if normalized is not None:
                    row.update({"error": normalized["public_message"], "failure": normalized})
            atomic_write(self.state_path, state)

    def save_result(self, row_id: str, result: Mapping[str, Any]) -> None:
        with self._lock:
            payload = copy.deepcopy(dict(result))
            for key in ("failure", "plan_failure", "twofa_failure", "live_check_failure"):
                if key in payload:
                    normalized = canonical_failure(payload.get(key) if isinstance(payload.get(key), Mapping) else None)
                    if normalized is None:
                        payload.pop(key, None)
                    else:
                        payload[key] = normalized
            atomic_write(self.results_dir / f"{fingerprint(row_id)}.json", payload)

    def result(self, row_id: str) -> dict[str, Any]:
        try:
            current = json.loads(
                (self.results_dir / f"{fingerprint(row_id)}.json").read_text(encoding="utf-8")
            )
        except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError):
            return {}
        return dict(current) if isinstance(current, dict) else {}

    def reveal_mailbox_url(self, row_id: str) -> str:
        row = self.entry(row_id)
        if row is None:
            raise FreeRegisterError(
                "free_mailbox_url", "读取 Free 取件地址", "Free 邮箱行不存在或已变化", retryable=False
            )
        return row.mailbox_url

    def delete(self, row_ids: Sequence[str]) -> int:
        requested = list(dict.fromkeys(str(value or "").strip().lower() for value in row_ids if str(value or "").strip()))
        if not requested:
            return 0
        with self._lock:
            entries = self.entries()
            by_id = {entry.row_id: entry for entry in entries}
            targets = [by_id[row_id] for row_id in requested if row_id in by_id]
            state = self._state()
            if any(str(state["rows"].get(row.row_id, {}).get("status") or "available") in ACTIVE_POOL_STATUSES for row in targets):
                raise FreeRegisterError(
                    "free_pool_delete",
                    "删除 Free 邮箱",
                    "选中的 Free 邮箱仍在排队或运行中，请等待任务结束后再删除",
                    retryable=False,
                )
            target_ids = {entry.row_id for entry in targets}
            self._write_entries([entry for entry in entries if entry.row_id not in target_ids])
            for row_id in target_ids:
                state["rows"].pop(row_id, None)
            atomic_write(self.state_path, state)
            return len(target_ids)

    def set_status(self, row_ids: Sequence[str], status: str) -> int:
        allowed = {"available", "unavailable", "draft", "pending_rerun"}
        if status not in allowed:
            raise FreeRegisterError("free_pool_status", "更新 Free 邮箱状态", "Free 邮箱状态无效", retryable=False)
        requested = {str(value or "").strip().lower() for value in row_ids if str(value or "").strip()}
        with self._lock:
            existing = {entry.row_id for entry in self.entries()}
            state = self._state()
            targets = requested & existing
            if any(str(state["rows"].get(row_id, {}).get("status") or "available") in ACTIVE_POOL_STATUSES for row_id in targets):
                raise FreeRegisterError(
                    "free_pool_status", "更新 Free 邮箱状态", "运行中的 Free 邮箱不能修改状态", retryable=False
                )
            for row_id in targets:
                row = state["rows"].setdefault(row_id, {})
                row["status"] = status
                if status == "available":
                    row.pop("cooldown_until", None)
            atomic_write(self.state_path, state)
            return len(targets)

    def counts(self) -> dict[str, int]:
        rows = self.public_rows()
        counts = {"total": len(rows), "available": 0, "running": 0, "success": 0, "partial_success": 0, "failed": 0, "pending_rerun": 0, "draft": 0, "unavailable": 0, "twofa_pending": 0}
        for row in rows:
            status = str(row.get("status") or "available")
            if status in ACTIVE_POOL_STATUSES:
                counts["running"] += 1
            elif status in counts:
                counts[status] += 1
        return counts

    def public_rows(self) -> list[dict[str, Any]]:
        with self._lock:
            state = self._state()["rows"]
            output = []
            for row in self.entries():
                current = state.get(row.row_id, {})
                result = self.result(row.row_id)
                current_status = str(current.get("status") or "available")
                if current_status in ACTIVE_POOL_STATUSES:
                    failure_source = current.get("failure")
                else:
                    failure_source = result.get("failure") if isinstance(result.get("failure"), Mapping) else current.get("failure")
                failure = canonical_failure(failure_source if isinstance(failure_source, Mapping) else None)
                plan_failure = canonical_failure(
                    result.get("plan_failure") if isinstance(result.get("plan_failure"), Mapping) else None,
                    default_node_code="free_plan_check",
                    default_node_label="查询 Free 套餐资格",
                )
                live_failure = canonical_failure(result.get("live_check_failure") if isinstance(result.get("live_check_failure"), Mapping) else None)
                output.append({
                    "row_id": row.row_id,
                    "line_no": row.line_no,
                    "email": row.email,
                    "status": current_status,
                    "cooldown_until": _cooldown_timestamp(current.get("cooldown_until")) or None,
                    "cooldown_remaining": max(0, int(_cooldown_timestamp(current.get("cooldown_until")) - time.time())),
                    "stage": current.get("stage", ""),
                    "batch_id": current.get("batch_id", ""),
                    "driver": result.get("driver") or current.get("driver", ""),
                    "proxy_masked": sanitize_failure_text(current.get("proxy_masked", ""), 300),
                    "proxy_fingerprint": current.get("proxy_fingerprint", ""),
                    "proxy_id": current.get("proxy_id", ""),
                    "proxy_scheme": current.get("proxy_scheme", ""),
                    "proxy_country": current.get("proxy_country", ""),
                    "proxy_group": current.get("proxy_group", ""),
                    "expected_exit_ip": result.get("expected_exit_ip") or current.get("expected_exit_ip", ""),
                    "registration_ip": result.get("registration_ip") or current.get("registration_ip", ""),
                    "exit_ip": result.get("exit_ip") or result.get("expected_exit_ip") or current.get("exit_ip", ""),
                    "profile_summary": sanitize_failure_text(result.get("profile_summary", ""), 300),
                    "account_flow": sanitize_failure_text(result.get("account_flow", ""), 120),
                    "plan_type": sanitize_failure_text(result.get("plan_type", ""), 120),
                    "subscription_plan": sanitize_failure_text(result.get("subscription_plan", ""), 120),
                    "has_active_subscription": bool(result.get("has_active_subscription", False)),
                    "plus_trial_eligible": bool(result.get("plus_trial_eligible", False)),
                    "eligible_campaign_id": sanitize_failure_text(result.get("eligible_campaign_id", ""), 160),
                    "plan_check_status": result.get("plan_check_status", ""),
                    "plan_check_task_id": result.get("plan_check_task_id", ""),
                    "plan_source": sanitize_failure_text(result.get("plan_source", ""), 80),
                    "plan_checked_at": result.get("plan_checked_at", ""),
                    "plan_retry_after_until": result.get("plan_retry_after_until"),
                    "plan_error_code": sanitize_failure_text(result.get("plan_error_code", ""), 160),
                    "plan_http_status": result.get("plan_http_status"),
                    "plan_failure": plan_failure,
                    "live_check_status": result.get("live_check_status", ""),
                    "live_check_mode": result.get("live_check_mode", ""),
                    "live_check_task_id": result.get("live_check_task_id", ""),
                    "live_checked_at": result.get("live_checked_at", ""),
                    "live_check_ip": result.get("live_check_ip", ""),
                    "live_check_token_refreshed": bool(result.get("live_check_token_refreshed", False)),
                    "live_check_http_status": result.get("live_check_http_status"),
                    "live_check_failure": live_failure,
                    "twofa_status": result.get("twofa_status", ""),
                    "twofa_error": sanitize_failure_text(result.get("twofa_error", ""), 300),
                    "has_access_token": bool(result.get("access_token")),
                    "has_password": bool(result.get("password")),
                    "has_totp": bool(result.get("totp_secret")),
                    "has_credential": bool(result.get("credential_line")),
                    "rebind_email": sanitize_failure_text(result.get("rebind_email", ""), 320),
                    "rebind_task_id": sanitize_failure_text(result.get("rebind_task_id", ""), 120),
                    "rebind_status": sanitize_failure_text(result.get("rebind_status", ""), 64),
                    "rebind_plan_type": sanitize_failure_text(result.get("rebind_plan_type", ""), 120),
                    "rebind_plus_trial_eligible": bool(result.get("rebind_plus_trial_eligible", False)),
                    "has_mailbox_url": True,
                    "task_id": result.get("task_id", ""),
                    "error": failure.get("public_message", "") if failure else sanitize_failure_text(current.get("error", "")),
                    "failure": failure,
                    "progress": copy.deepcopy(current.get("progress")) if isinstance(current.get("progress"), Mapping) else None,
                })
            return output

    def export_success(self, row_ids: Sequence[str] = ()) -> str:
        selected = {str(value or "").strip().lower() for value in row_ids if str(value or "").strip()}
        values: list[str] = []
        for row in self.entries():
            if selected and row.row_id not in selected:
                continue
            result = self.result(row.row_id)
            if result.get("status") not in (None, "", "success") and not result.get("access_token"):
                continue
            credential = str(result.get("credential_line") or "").strip()
            token = str(result.get("access_token") or "").strip()
            if credential or token:
                values.append(credential or f"{row.email}----{token}")
        return "\n".join(values)

    def build_transfer_content(
        self,
        row_ids: Sequence[str] = (),
        *,
        include_password: bool = True,
    ) -> dict[str, Any]:
        """Build ordinary mailbox-pool rows from explicitly selected Free rows."""
        requested = list(dict.fromkeys(
            str(value or "").strip().lower()
            for value in row_ids
            if str(value or "").strip()
        ))
        if not requested:
            return {
                "content": "",
                "selected": 0,
                "prepared": 0,
                "skipped": 1,
                "skipped_items": [{
                    "row_id": "",
                    "email": "",
                    "reason": "没有提供有效的 Free 邮箱选择",
                }],
            }
        selected = set(requested)
        lines: list[str] = []
        skipped: list[dict[str, str]] = []
        state = self._state()["rows"]
        for row in self.entries():
            if selected and row.row_id not in selected:
                continue
            current = state.get(row.row_id, {}) if isinstance(state, Mapping) else {}
            status = str(current.get("status") or "available").strip().lower()
            if status in ACTIVE_POOL_STATUSES:
                skipped.append({"row_id": row.row_id, "email": row.email, "reason": "该 Free 邮箱仍在注册或测活任务中"})
                continue
            result = self.result(row.row_id)
            live_status = str(result.get("live_check_status") or "").strip().lower()
            if live_status in {"queued", "running"}:
                skipped.append({"row_id": row.row_id, "email": row.email, "reason": "该 Free 邮箱仍在测活中"})
                continue
            if not result:
                skipped.append({"row_id": row.row_id, "email": row.email, "reason": "该 Free 邮箱没有注册结果，暂不可传输"})
                continue
            password = str(result.get("password") or "").strip()
            totp_secret = str(result.get("totp_secret") or "").strip()
            fields = [row.email]
            if password and include_password:
                fields.append(password)
            fields.append(row.mailbox_url)
            if totp_secret:
                fields.append(totp_secret)
            lines.append("----".join(fields))
        requested_missing = selected - {row.row_id for row in self.entries()}
        skipped.extend({"row_id": row_id, "email": "", "reason": "Free 邮箱行不存在或已变化"} for row_id in sorted(requested_missing))
        return {
            "content": "\n".join(lines),
            "selected": len(requested) if requested else len(lines),
            "prepared": len(lines),
            "skipped": len(skipped),
            "skipped_items": skipped,
        }


class FreeProxyPool:
    def __init__(self, data_dir: str | Path, *, default_scheme: str = DEFAULT_FREE_PROXY_SCHEME) -> None:
        self.data_dir = Path(data_dir).expanduser().resolve()
        self.path = self.data_dir / "free_proxy_pool.txt"
        scheme = str(default_scheme or DEFAULT_FREE_PROXY_SCHEME).strip().lower()
        self.default_scheme = scheme if scheme in FREE_PROXY_SCHEMES else DEFAULT_FREE_PROXY_SCHEME

    def import_text(self, content: str) -> int:
        incoming = [normalized for row in str(content or "").splitlines() if (normalized := normalize_proxy_value(row, default_scheme=self.default_scheme))]
        if not incoming:
            raise FreeRegisterError("free_proxy_pool", "Free 代理池", "Free 代理池没有有效代理")
        existing = self.values()
        seen = set(existing)
        valid = list(existing)
        for value in incoming:
            if value in seen:
                continue
            seen.add(value)
            valid.append(value)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.path.write_text("\n".join(valid) + "\n", encoding="utf-8")
        os.chmod(self.path, 0o600)
        return len(valid) - len(existing)

    def values(self, content: str = "") -> list[str]:
        if content.strip():
            rows = content.splitlines()
        else:
            try:
                rows = self.path.read_text(encoding="utf-8").splitlines()
            except (FileNotFoundError, OSError, UnicodeError):
                rows = []
        return [normalized for row in rows if (normalized := normalize_proxy_value(row, default_scheme=self.default_scheme))]

    def public(self) -> dict[str, Any]:
        values = self.values()
        return {"count": len(values), "rows": [{"index": index, "masked": mask_proxy(value), "fingerprint": fingerprint(value)} for index, value in enumerate(values, 1)]}

    @staticmethod
    def _probe(proxy: str, target: str) -> str:
        from curl_cffi import requests as curl_requests

        session = curl_requests.Session(impersonate="chrome", verify=False)
        session.proxies = {"http": proxy, "https": proxy}
        try:
            response = session.get(target, headers={"Accept": "text/plain", "Cache-Control": "no-cache"}, timeout=12)
        finally:
            close = getattr(session, "close", None)
            if callable(close):
                close()
        status = int(getattr(response, "status_code", 0) or 0)
        if not 200 <= status < 300:
            raise ValueError(f"代理探测请求返回 HTTP {status}")
        value = bytes(getattr(response, "content", b"") or b"")[:128].decode("utf-8", "ignore").strip()
        if not re.fullmatch(r"[0-9a-fA-F:.]{3,64}", value):
            raise ValueError("代理探测响应格式无效")
        return value

    def bind(self, count: int, *, content: str = "", probe: Callable[[str, str], str] | None = None, probe_url: str = "https://api.ipify.org") -> list[ProxyBinding]:
        values = self.values(content)
        if not values:
            raise FreeRegisterError("free_proxy_preflight", "Free 代理预检", "Free 代理池没有有效代理", retryable=False)
        selected = [values[index % len(values)] for index in range(max(0, int(count)))]
        fingerprints = [fingerprint(value) for value in selected]
        check = probe or self._probe
        exit_ips: list[str] = []
        for index, value in enumerate(selected, 1):
            try:
                exit_ips.append(str(check(value, probe_url)).strip())
            except FreeRegisterError:
                raise
            except Exception as exc:
                raise FreeRegisterError(
                    "free_proxy_preflight", "Free 代理预检",
                    f"代理池第 {index} 条代理探测失败：{proxy_error_detail(exc)}",
                ) from exc
        return [ProxyBinding(value, fp, mask_proxy(value), ip) for value, fp, ip in zip(selected, fingerprints, exit_ips)]

    def verify(self, binding: ProxyBinding, *, probe: Callable[[str, str], str] | None = None, probe_url: str = "https://api.ipify.org") -> str:
        try:
            current = str((probe or self._probe)(binding.proxy, probe_url)).strip()
        except Exception as exc:
            raise FreeRegisterError("proxy_connect_failed", "代理连接失败", f"代理连通性检查失败：{proxy_error_detail(exc)}") from exc
        return current


class FreeTaskStore:
    def __init__(self, data_dir: str | Path) -> None:
        self.path = Path(data_dir).expanduser().resolve() / "tasks.json"
        self._lock = threading.RLock()

    def load(self) -> dict[str, dict[str, Any]]:
        with self._lock:
            try:
                payload = json.loads(self.path.read_text(encoding="utf-8"))
            except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError):
                return {}
            tasks = payload.get("tasks") if isinstance(payload, Mapping) else {}
            return {str(key): dict(value) for key, value in tasks.items() if isinstance(value, Mapping)} if isinstance(tasks, Mapping) else {}

    def save(self, tasks: Mapping[str, Mapping[str, Any]]) -> None:
        with self._lock:
            atomic_write(self.path, {"version": 1, "tasks": copy.deepcopy(dict(tasks))})


# Keep the historical import path while moving all runtime calls to the
# structured Free-only resource store.
FreeProxyPool = StructuredFreeProxyPool

__all__ = ["FreeMailboxPool", "FreeProxyPool", "FreeTaskStore"]
