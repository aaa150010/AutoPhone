"""Testable mailbox administration for the recovered web runtime."""

from __future__ import annotations

import json
from pathlib import Path
import re
from threading import RLock
import time
from typing import Any, Callable, Mapping, Protocol, Sequence
import urllib.parse

try:
    from .chatgpt_totp import parse_chatgpt_totp_row, totp_code as generate_totp_code
except ImportError:  # Loaded as a top-level override module by the Mac launcher.
    from chatgpt_totp import parse_chatgpt_totp_row, totp_code as generate_totp_code


_EMAIL_RE = re.compile(
    r"(?i)\b[a-z0-9][a-z0-9._%+-]*@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b"
)
_PROGRESS_FIELDS = ("code", "label", "group", "entered_at", "finished_at")
_SECRET_MASK = "********"


class ConfigStore(Protocol):
    data_dir: str | Path

    def load(self) -> dict[str, Any]: ...


def email_from_row(row: Any) -> str:
    match = _EMAIL_RE.search(str(row or ""))
    return match.group(0).lower() if match else ""


def parse_oauth_mailbox_row(row: Any) -> tuple[str, str, str, str] | None:
    raw = str(row or "").strip()
    if "----" not in raw:
        return None
    parts = [part.strip() for part in raw.split("----")]
    if len(parts) < 4:
        return None
    email = email_from_row(parts[0])
    password, oauth_client_id, oauth_refresh_token = parts[1], parts[2], parts[3]
    if not email or not password or not oauth_client_id or not oauth_refresh_token:
        return None
    return email, password, oauth_client_id, oauth_refresh_token


def is_importable_mailbox_row(row: Any) -> bool:
    raw = str(row or "").strip()
    if not raw or raw.startswith("#") or not email_from_row(raw):
        return False
    if "----" in raw:
        return len([part for part in raw.split("----") if part.strip()]) >= 2
    if "|" in raw:
        return len([part for part in raw.split("|") if part.strip()]) >= 3
    return False


def password_from_row(row: Any) -> str:
    raw = str(row or "").strip()
    if not raw:
        return ""
    delimiter = "----" if "----" in raw else "|" if "|" in raw else ""
    if not delimiter:
        return ""
    parts = [part.strip() for part in raw.split(delimiter)]
    return parts[1] if len(parts) >= 2 else ""


def masked_source_row(row: Any) -> str:
    raw = str(row or "").strip()
    email = email_from_row(raw)
    if not email:
        return ""
    if parse_chatgpt_totp_row(raw) is not None:
        return f"{email}|{_SECRET_MASK}|{_SECRET_MASK}"
    if "----" in raw:
        field_count = max(2, len(raw.split("----")))
        return "----".join((email, *([_SECRET_MASK] * (field_count - 1))))
    return email


def selected_line_numbers(payload: Any) -> list[int]:
    value = payload if isinstance(payload, Mapping) else {}
    result = []
    for item in value.get("line_nos") or []:
        try:
            number = int(item)
        except (TypeError, ValueError):
            continue
        if number > 0:
            result.append(number)
    return sorted(set(result))


def pool_count_status(state_item: Any, now: float | int | None = None) -> str:
    item = state_item if isinstance(state_item, Mapping) else {}
    status = str(item.get("status") or "").lower()
    if status in {"damaged", "consumed"}:
        return status
    if status == "leased":
        try:
            lease_until = float(item.get("lease_until") or 0)
        except (TypeError, ValueError):
            lease_until = 0
        if lease_until > (time.time() if now is None else now):
            return "running"
    return "available"


def human_mailbox_status(state_item: Any, now: float | int | None = None) -> tuple[str, str]:
    status = pool_count_status(state_item, now)
    if status == "running":
        return "running", "运行中"
    if status == "consumed":
        return "consumed", "已使用"
    if status == "damaged":
        return "failed", "失败"
    return "available", "可用"


def friendly_mailbox_error(error: Any) -> str:
    value = str(error or "")
    status_messages = {
        "stopped": "任务已停止",
        "stopped_before_start": "任务开始前已停止",
        "manual_restore": "",
    }
    if value in status_messages:
        return status_messages[value]
    if "deleted or deactivated" in value or "You do not have an account" in value:
        return "邮箱对应的 OpenAI 账号不可用（已删除或停用）"
    if "email_otp_failed" in value:
        return "邮箱验证码提交后被 OpenAI 拒绝，请确认该邮箱对应的 OpenAI 账号是否可用"
    return value


def redact_mailbox_credentials(error: Any, secrets: Sequence[Any]) -> str:
    text = str(error or "")
    candidates = {str(secret) for secret in secrets if str(secret or "")}
    encoded = {
        urllib.parse.quote(secret, safe="")
        for secret in candidates
        if urllib.parse.quote(secret, safe="") != secret
    }
    for secret in sorted(candidates | encoded, key=len, reverse=True):
        text = re.sub(re.escape(secret), _SECRET_MASK, text, flags=re.IGNORECASE)
    return text


def resolve_config_path(store: ConfigStore, value: Any) -> Path:
    target = Path(value or "")
    if not target.is_absolute():
        target = Path(store.data_dir) / target
    return target


class MailboxAdminService:
    """Mailbox operations with recovered-runtime dependencies supplied as callables."""

    def __init__(
        self,
        store: ConfigStore,
        *,
        validate_pool: Callable[[dict[str, Any]], Any],
        imap_poller_factory: Callable[..., Any],
        runtime_status: Callable[[dict[str, Any]], Mapping[str, Any]] | None = None,
        progress_lookup: Callable[[str], Mapping[str, Any] | None] | None = None,
        is_active_progress: Callable[[Any, Any], bool] | None = None,
        log_fn: Callable[[str, str], None] | None = None,
        error_formatter: Callable[[Any], str] = str,
        now_fn: Callable[[], float] = time.time,
    ) -> None:
        self.store = store
        self.validate_pool = validate_pool
        self.imap_poller_factory = imap_poller_factory
        self.runtime_status = runtime_status
        self.progress_lookup = progress_lookup
        self.is_active_progress = is_active_progress or (lambda _progress, _status: False)
        self.log_fn = log_fn
        self.error_formatter = error_formatter
        self.now_fn = now_fn
        self._lock = RLock()

    def _config(self) -> dict[str, Any]:
        value = self.store.load()
        return dict(value) if isinstance(value, Mapping) else {}

    def _path(self, config: Mapping[str, Any], name: str) -> Path:
        return resolve_config_path(self.store, config.get(name))

    @staticmethod
    def _read_json_file(path: Path) -> dict[str, Any]:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return {}
        return value if isinstance(value, dict) else {}

    @staticmethod
    def _write_json_file(path: Path, value: Mapping[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")

    def _read_pool_lines(self, config: Mapping[str, Any] | None = None) -> list[str]:
        cfg = config or self._config()
        pool_path = self._path(cfg, "pool_path")
        if not pool_path.exists():
            return []
        return [
            line.strip()
            for line in pool_path.read_text(encoding="utf-8-sig").splitlines()
            if line.strip()
        ]

    def _write_pool_lines(self, lines: Sequence[str], config: Mapping[str, Any] | None = None) -> Path:
        cfg = config or self._config()
        pool_path = self._path(cfg, "pool_path")
        pool_path.parent.mkdir(parents=True, exist_ok=True)
        content = "\n".join(lines).strip()
        pool_path.write_text(f"{content}\n" if content else "", encoding="utf-8")
        return pool_path

    def _validate_pool(self) -> Any:
        return self.validate_pool(self._config())

    def _log(self, message: str, level: str) -> None:
        if self.log_fn is not None:
            self.log_fn(message, level)

    def _format_error(self, error: Any, secrets: Sequence[Any] = ()) -> str:
        try:
            value = self.error_formatter(error)
        except Exception:
            value = str(error)
        return redact_mailbox_credentials(value, secrets)

    @staticmethod
    def _row_secrets(row: str) -> tuple[str, ...]:
        values = [row, email_from_row(row), password_from_row(row)]
        if "|" in row:
            values.extend(part.strip() for part in row.split("|")[1:])
        oauth = parse_oauth_mailbox_row(row)
        if oauth is not None:
            values.extend(oauth)
        totp = parse_chatgpt_totp_row(row)
        if totp is not None:
            values.extend(totp)
        return tuple(dict.fromkeys(value for value in values if value))

    def pool_row_by_line(self, line_no: Any) -> tuple[str, str]:
        try:
            target = int(line_no)
        except (TypeError, ValueError):
            return "", ""
        if target <= 0:
            return "", ""
        with self._lock:
            lines = self._read_pool_lines()
            if target > len(lines):
                return "", ""
            row = lines[target - 1]
        return row, email_from_row(row)

    def latest_code(self, payload: Any) -> dict[str, Any]:
        value = payload if isinstance(payload, Mapping) else {}
        row, email = self.pool_row_by_line(value.get("line_no"))
        if not row:
            return {"ok": False, "error": "没有找到这一行邮箱"}

        parsed_totp = parse_chatgpt_totp_row(row)
        if parsed_totp is not None:
            account, _password, secret = parsed_totp
            now = self.now_fn()
            code = generate_totp_code(secret, now=now)
            remaining = 30 - (int(now) % 30)
            return {
                "ok": True,
                "kind": "totp",
                "email": account,
                "code": code,
                "remaining": remaining,
                "message": f"当前 2FA 验证码，约 {remaining} 秒后刷新",
            }

        parts = [part.strip() for part in row.split("----")]
        password = parts[1] if len(parts) >= 2 else ""
        oauth_client_id = parts[2] if len(parts) >= 3 else ""
        oauth_refresh_token = parts[3] if len(parts) >= 4 else ""
        if not email or not password:
            return {"ok": False, "error": "这一行没有可用于 IMAP 查询的邮箱密码"}

        poller = None
        try:
            poller = self.imap_poller_factory(
                email,
                password,
                verbose=False,
                oauth_client_id=oauth_client_id,
                oauth_refresh_token=oauth_refresh_token,
                proxy="",
            )
            now = self.now_fn()
            code = poller.poll_code(
                timeout=5,
                interval=1,
                since_ts=now - 1800,
                recent_scan_limit=40,
                include_existing=True,
            )
        except Exception as exc:
            error = self._format_error(exc, self._row_secrets(row))
            return {"ok": False, "error": f"IMAP 查询失败: {error}"}
        finally:
            if poller is not None:
                try:
                    poller.close()
                except Exception:
                    pass

        if not code:
            return {
                "ok": True,
                "kind": "email",
                "email": email,
                "code": "",
                "message": "未找到新的 OpenAI 邮箱验证码",
            }
        return {
            "ok": True,
            "kind": "email",
            "email": email,
            "code": str(code),
            "message": "已找到最新 OpenAI 邮箱验证码",
        }

    def _latest_results_by_email(self, results_dir: Path) -> dict[str, dict[str, Any]]:
        latest: dict[str, dict[str, Any]] = {}
        if not results_dir.exists():
            return latest
        for path in sorted(results_dir.glob("*.json")):
            data = self._read_json_file(path)
            email = email_from_row(data.get("email") or data.get("source_row") or "")
            if not email:
                continue
            try:
                fallback_created = path.stat().st_mtime
            except OSError:
                fallback_created = 0
            try:
                created = int(data.get("created_at") or data.get("updated_at") or fallback_created)
            except (TypeError, ValueError):
                created = int(fallback_created)
            previous = latest.get(email)
            if previous is None or created >= int(previous.get("_created") or 0):
                data["_created"] = created
                latest[email] = data
        return latest

    def _live_progress_by_email(self, config: dict[str, Any]) -> dict[str, dict[str, Any]]:
        if self.runtime_status is None or self.progress_lookup is None:
            return {}
        try:
            runtime = self.runtime_status(config)
        except Exception:
            return {}
        if not isinstance(runtime, Mapping):
            return {}

        latest: dict[str, dict[str, Any]] = {}
        for task in runtime.get("tasks") or []:
            if not isinstance(task, Mapping):
                continue
            email = email_from_row(task.get("email") or task.get("account") or "")
            task_id = str(task.get("task_id") or "").strip()
            if not email or not task_id:
                continue
            try:
                raw_progress = self.progress_lookup(task_id)
            except Exception:
                continue
            if not isinstance(raw_progress, Mapping):
                continue
            progress = {
                field: raw_progress.get(field)
                for field in _PROGRESS_FIELDS
                if field in raw_progress
            }
            try:
                updated_at = int(task.get("updated_at") or task.get("created_at") or 0)
            except (TypeError, ValueError):
                updated_at = 0
            previous = latest.get(email)
            if previous is None or updated_at >= previous["updated_at"]:
                latest[email] = {
                    "task_id": task_id,
                    "task_status": str(task.get("status") or ""),
                    "progress": progress,
                    "updated_at": updated_at,
                }
        return latest

    def list_mailboxes(self) -> dict[str, Any]:
        with self._lock:
            config = self._config()
            pool_path = self._path(config, "pool_path")
            state_path = self._path(config, "state_path")
            results_dir = self._path(config, "results_dir")
            lines = self._read_pool_lines(config)
            state = self._read_json_file(state_path)

        state_by_line: dict[int, Mapping[str, Any]] = {}
        state_by_email: dict[str, Mapping[str, Any]] = {}
        items = state.get("items") if isinstance(state.get("items"), Mapping) else {}
        for item in items.values():
            if not isinstance(item, Mapping):
                continue
            email = email_from_row(item.get("email") or "")
            try:
                line_no = int(item.get("line_no") or 0)
            except (TypeError, ValueError):
                line_no = 0
            if line_no > 0:
                state_by_line[line_no] = item
            if email:
                state_by_email[email] = item

        latest_results = self._latest_results_by_email(results_dir)
        live_progress = self._live_progress_by_email(config)
        rows = []
        counts = {"total": 0, "available": 0, "running": 0, "success": 0, "failed": 0}
        now = self.now_fn()
        for index, row in enumerate(lines, start=1):
            email = email_from_row(row)
            state_item = state_by_line.get(index) or state_by_email.get(email) or {}
            row_secrets = self._row_secrets(row)
            result = latest_results.get(email) or {}
            live_task = live_progress.get(email) or {}
            state_reason = self._format_error(state_item.get("reason") or "", row_secrets)
            manually_restored = (
                str(state_item.get("status") or "").lower() == "available"
                and str(state_item.get("reason") or "") == "manual_restore"
            )
            if manually_restored:
                result = {}
            result_status = str(result.get("status") or "").lower()
            result_payload = result.get("result") if isinstance(result.get("result"), Mapping) else {}
            detail_error = (
                result.get("technical_error")
                or result_payload.get("local_oauth_exchange_error")
                or result_payload.get("error")
                or result.get("error")
                or ("" if manually_restored else state_reason)
                or ""
            )
            detail_error = self._format_error(detail_error, row_secrets)
            friendly_error = friendly_mailbox_error(detail_error)
            succeeded = result_status in {"success", "ok", "uploaded"}
            sms_cost_usd = result_payload.get("sms_cost_usd", result.get("sms_cost_usd")) if succeeded else None
            sms_cost_cny = result_payload.get("sms_cost_cny", result.get("sms_cost_cny")) if succeeded else None
            sms_exchange_rate = (
                result_payload.get("sms_exchange_rate", result.get("sms_exchange_rate")) if succeeded else None
            )
            sms_exchange_date = (
                result_payload.get("sms_exchange_date", result.get("sms_exchange_date")) if succeeded else ""
            )
            status_key, status_label = human_mailbox_status(state_item, now)
            progress = live_task.get("progress")
            task_status = live_task.get("task_status")
            try:
                live_active = self.is_active_progress(progress, task_status)
            except Exception:
                live_active = False
            if live_active:
                status_key, status_label = "running", "运行中"
            counts["total"] += 1
            count_status = "running" if live_active else pool_count_status(state_item, now)
            if count_status == "consumed":
                count_status = "success"
            counts[count_status] = counts.get(count_status, 0) + 1
            rows.append(
                {
                    "line_no": index,
                    "email": email,
                    "password": _SECRET_MASK if password_from_row(row) else "",
                    "status": status_key,
                    "status_label": status_label,
                    "pool_status": state_item.get("status") or "available",
                    "reason": state_reason,
                    "error": friendly_error,
                    "technical_error": detail_error,
                    "task_id": live_task.get("task_id") or result.get("task_id") or "",
                    "task_status": task_status or result_status,
                    "progress": progress,
                    "sms_cost_usd": sms_cost_usd,
                    "sms_cost_cny": sms_cost_cny,
                    "sms_exchange_rate": sms_exchange_rate,
                    "sms_exchange_date": sms_exchange_date or "",
                    "updated_at": result.get("created_at") or state_item.get("updated_at") or 0,
                    "source_row": masked_source_row(row),
                }
            )
        return {"ok": True, "counts": counts, "rows": rows, "pool_path": str(pool_path)}

    def import_mailboxes(self, content: Any) -> dict[str, Any]:
        new_lines = [
            line.strip()
            for line in str(content or "").splitlines()
            if is_importable_mailbox_row(line)
        ]
        if not new_lines:
            return {"ok": False, "error": "请粘贴要导入的邮箱"}

        with self._lock:
            config = self._config()
            old_lines = self._read_pool_lines(config)
            seen = {line.lower() for line in old_lines}
            appended = []
            skipped = 0
            for line in new_lines:
                if line.lower() in seen:
                    skipped += 1
                    continue
                seen.add(line.lower())
                appended.append(line)
            if not appended:
                return {"ok": False, "error": "没有新增邮箱，可能都是重复行"}
            self._write_pool_lines(old_lines + appended, config)
            check = self._validate_pool()

        self._log(f"邮箱管理追加导入: 新增 {len(appended)} 条，跳过重复 {skipped} 条", "success")
        return {"ok": True, "imported": len(appended), "skipped": skipped, "validate": check}

    def _rewrite_state_after_delete(
        self,
        kept_lines: Sequence[str],
        deleted_line_nos: set[int],
        deleted_emails: set[str],
        config: Mapping[str, Any],
    ) -> None:
        state_path = self._path(config, "state_path")
        state = self._read_json_file(state_path)
        items = state.get("items") if isinstance(state.get("items"), Mapping) else {}
        kept_email_to_line = {
            email_from_row(row): index
            for index, row in enumerate(kept_lines, start=1)
            if email_from_row(row)
        }
        new_items = {}
        for key, raw_item in items.items():
            if not isinstance(raw_item, Mapping):
                continue
            item = dict(raw_item)
            email = email_from_row(item.get("email") or "")
            try:
                line_no = int(item.get("line_no") or 0)
            except (TypeError, ValueError):
                line_no = 0
            if line_no in deleted_line_nos or email in deleted_emails:
                continue
            if email in kept_email_to_line:
                item["line_no"] = kept_email_to_line[email]
                new_items[key] = item
        state["items"] = new_items
        state["updated_at"] = int(self.now_fn())
        self._write_json_file(state_path, state)

    def delete_mailboxes(self, payload: Any) -> dict[str, Any]:
        selected = selected_line_numbers(payload)
        if not selected:
            return {"ok": False, "error": "请先勾选要删除的邮箱"}

        with self._lock:
            config = self._config()
            lines = self._read_pool_lines(config)
            selected_set = set(selected)
            deleted_lines = [line for index, line in enumerate(lines, start=1) if index in selected_set]
            kept_lines = [line for index, line in enumerate(lines, start=1) if index not in selected_set]
            if not deleted_lines:
                return {"ok": False, "error": "选中的邮箱不存在或已经删除"}
            self._write_pool_lines(kept_lines, config)
            deleted_emails = {email_from_row(line) for line in deleted_lines if email_from_row(line)}
            self._rewrite_state_after_delete(kept_lines, selected_set, deleted_emails, config)
            self._validate_pool()

        self._log(f"邮箱管理删除: {len(deleted_lines)} 条", "warn")
        return {"ok": True, "deleted": len(deleted_lines)}

    def restore_mailboxes(self, payload: Any) -> dict[str, Any]:
        selected = selected_line_numbers(payload)
        if not selected:
            return {"ok": False, "error": "请先勾选要放回可领取的邮箱"}

        with self._lock:
            config = self._config()
            lines = self._read_pool_lines(config)
            selected_set = set(selected)
            selected_emails = {
                email_from_row(line)
                for index, line in enumerate(lines, start=1)
                if index in selected_set and email_from_row(line)
            }
            if not selected_emails:
                return {"ok": False, "error": "选中的邮箱不存在"}
            self._validate_pool()
            state_path = self._path(config, "state_path")
            state = self._read_json_file(state_path)
            items = state.get("items") if isinstance(state.get("items"), Mapping) else {}
            restored = 0
            now = int(self.now_fn())
            for item in items.values():
                if not isinstance(item, dict):
                    continue
                email = email_from_row(item.get("email") or "")
                if email not in selected_emails:
                    continue
                item.update({"status": "available", "lease_until": 0, "reason": "manual_restore", "updated_at": now})
                history = item.setdefault("history", [])
                if isinstance(history, list):
                    history.append({"event": "restored", "reason": "manual_restore", "at": now})
                restored += 1
            if restored == 0:
                restored = len(selected_emails)
            state["updated_at"] = now
            self._write_json_file(state_path, state)

        self._log(f"邮箱管理放回可领取: {restored} 条", "success")
        return {"ok": True, "restored": restored}

    def rows(self) -> dict[str, Any]:
        return self.list_mailboxes()

    def append(self, content: Any) -> dict[str, Any]:
        return self.import_mailboxes(content)

    def delete(self, payload: Any) -> dict[str, Any]:
        return self.delete_mailboxes(payload)

    def restore(self, payload: Any) -> dict[str, Any]:
        return self.restore_mailboxes(payload)


__all__ = [
    "ConfigStore",
    "MailboxAdminService",
    "email_from_row",
    "friendly_mailbox_error",
    "generate_totp_code",
    "human_mailbox_status",
    "is_importable_mailbox_row",
    "masked_source_row",
    "parse_chatgpt_totp_row",
    "parse_oauth_mailbox_row",
    "password_from_row",
    "pool_count_status",
    "redact_mailbox_credentials",
    "resolve_config_path",
    "selected_line_numbers",
]
