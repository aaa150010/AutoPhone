"""Testable mailbox administration for the recovered web runtime."""

from __future__ import annotations

import hmac
import json
from pathlib import Path
import re
from threading import RLock
import time
from typing import Any, Callable, Mapping, Protocol, Sequence

try:
    from .mailbox_source_lock import MailboxSourceLockMixin
except ImportError:  # Loaded as a top-level override module by the Mac launcher.
    from mailbox_source_lock import MailboxSourceLockMixin

try:
    from .mailbox_import_runtime import MailboxImportMixin
except ImportError:  # Loaded as a top-level override module by the Mac launcher.
    from mailbox_import_runtime import MailboxImportMixin

try:
    from .mailbox_selection import resolve_source_rows
except ImportError:  # Loaded as a top-level override module by the Mac launcher.
    from mailbox_selection import resolve_source_rows

try:
    from .chatgpt_totp import totp_code as generate_totp_code
except ImportError:  # Loaded as a top-level override module by the Mac launcher.
    from chatgpt_totp import totp_code as generate_totp_code

try:
    from .mailbox_url_runtime import MailboxUrlClient
except ImportError:  # Loaded as a top-level override module by the Mac launcher.
    from mailbox_url_runtime import MailboxUrlClient

try:
    from .mailbox_row_formats import (
        email_from_row,
        is_importable_mailbox_row,
        mailbox_url_from_row,
        masked_source_row,
        parse_chatgpt_totp_row,
        parse_mailbox_url_row,
        parse_mailbox_url_totp_row,
        parse_mailbox_password_url_row,
        parse_oauth_mailbox_row,
        parse_plain_password_mailbox_row,
        password_from_row,
        public_task_account,
        row_id_from_source,
        row_secrets,
        totp_secret_from_row,
    )
except ImportError:  # Loaded as a top-level override module by the Mac launcher.
    from mailbox_row_formats import (
        email_from_row,
        is_importable_mailbox_row,
        mailbox_url_from_row,
        masked_source_row,
        parse_chatgpt_totp_row,
        parse_mailbox_url_row,
        parse_mailbox_url_totp_row,
        parse_mailbox_password_url_row,
        parse_oauth_mailbox_row,
        parse_plain_password_mailbox_row,
        password_from_row,
        public_task_account,
        row_id_from_source,
        row_secrets,
        totp_secret_from_row,
    )

try:
    from .error_observability import public_failure
except ImportError:  # Loaded as a top-level override module by the Mac launcher.
    from error_observability import public_failure

try:
    from .mailbox_redaction import redact_mailbox_credentials, url_credential_secrets
except ImportError:  # Loaded as a top-level override module by the Mac launcher.
    from mailbox_redaction import redact_mailbox_credentials, url_credential_secrets

try:
    from .mailbox_quota_service import query_openai_quotas as run_openai_quota_query
except ImportError:  # Loaded as a top-level override module by the Mac launcher.
    from mailbox_quota_service import query_openai_quotas as run_openai_quota_query

try:
    from .mailbox_openai_test_service import test_openai_mailboxes as run_openai_test
except ImportError:  # Loaded as a top-level override module by the Mac launcher.
    from mailbox_openai_test_service import test_openai_mailboxes as run_openai_test

try:
    from .mailbox_state_runtime import (
        friendly_mailbox_error,
        human_mailbox_status,
        indexed_mailbox_state,
        index_mailbox_states,
        latest_batch_members_by_row,
        manual_sms_received,
        pool_count_status,
        public_batch_metadata,
        public_mailbox_reason,
        restore_mailbox_rows,
        rewrite_state_after_delete,
        selected_line_numbers,
    )
except ImportError:  # Loaded as a top-level override module by the Mac launcher.
    from mailbox_state_runtime import (
        friendly_mailbox_error,
        human_mailbox_status,
        indexed_mailbox_state,
        index_mailbox_states,
        latest_batch_members_by_row,
        manual_sms_received,
        pool_count_status,
        public_batch_metadata,
        public_mailbox_reason,
        restore_mailbox_rows,
        rewrite_state_after_delete,
        selected_line_numbers,
    )

try:
    from .openai_quota_runtime import (
        OpenAIQuotaError,
        credentials_from_result,
    )
except ImportError:  # Loaded as a top-level override module by the Mac launcher.
    from openai_quota_runtime import (
        OpenAIQuotaError,
        credentials_from_result,
    )

try:
    from .openai_row_status import (
        public_sub2_status,
        resolve_openai_status,
        resolve_quota_status,
    )
except ImportError:  # Loaded as a top-level override module by the Mac launcher.
    from openai_row_status import (
        public_sub2_status,
        resolve_openai_status,
        resolve_quota_status,
    )

try:
    from .mailbox_sub2_results import (
        latest_sub2_accounts_by_email,
        sub2_account_id_from_result,
    )
except ImportError:  # Loaded as a top-level override module by the Mac launcher.
    from mailbox_sub2_results import (
        latest_sub2_accounts_by_email,
        sub2_account_id_from_result,
    )

try:
    from .mailbox_result_index import MailboxResultIndex
except ImportError:  # Loaded as a top-level override module by the Mac launcher.
    from mailbox_result_index import MailboxResultIndex

_PROGRESS_FIELDS = ("code", "label", "group", "entered_at", "finished_at", "timing")
_SECRET_MASK = "********"


class ConfigStore(Protocol):
    data_dir: str | Path

    def load(self) -> dict[str, Any]: ...


def resolve_config_path(store: ConfigStore, value: Any) -> Path:
    target = Path(value or "")
    if not target.is_absolute():
        target = Path(store.data_dir) / target
    return target


class MailboxAdminService(MailboxImportMixin, MailboxSourceLockMixin):
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
        sub2_status_lookup: Callable[[str], Mapping[str, Any] | None] | None = None,
        sub2_batch_tester: Callable[[Sequence[Mapping[str, Any]]], Mapping[str, Any]] | None = None,
        openai_status_lookup: Callable[[str], Mapping[str, Any] | None] | None = None,
        openai_direct_batch_tester: Callable[[Sequence[Mapping[str, Any]], str], Mapping[str, Any]] | None = None,
        mailbox_url_reader_factory: Callable[..., Any] | None = None,
        openai_quota_query: Callable[[Mapping[str, Any], str], Mapping[str, Any]] | None = None,
        openai_quota_status_lookup: Callable[[str], Mapping[str, Any] | None] | None = None,
        openai_quota_status_store: Callable[[str, Mapping[str, Any]], Mapping[str, Any] | None] | None = None,
        phone_risk_lookup: Callable[[str], Mapping[str, Any] | None] | None = None,
        next_batch_priority: Any = None,
        run_batch_membership: Callable[..., Sequence[Mapping[str, Any]]] | None = None,
        current_run_append: Callable[[Sequence[str]], Mapping[str, Any]] | None = None,
        result_index: MailboxResultIndex | None = None,
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
        self.sub2_status_lookup = sub2_status_lookup
        self.sub2_batch_tester = sub2_batch_tester
        self.openai_status_lookup = openai_status_lookup
        self.openai_direct_batch_tester = openai_direct_batch_tester
        self.mailbox_url_reader_factory = mailbox_url_reader_factory or MailboxUrlClient
        self.openai_quota_query = openai_quota_query
        self.openai_quota_status_lookup = openai_quota_status_lookup
        self.openai_quota_status_store = openai_quota_status_store
        self.phone_risk_lookup = phone_risk_lookup
        self.next_batch_priority = next_batch_priority
        self.run_batch_membership = run_batch_membership
        self.current_run_append = current_run_append
        self.result_index = result_index or MailboxResultIndex(now_fn=now_fn)
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
        return row_secrets(row)

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

    def reveal_password(self, row_id: Any, line_no: Any) -> dict[str, Any]:
        expected_row_id = str(row_id or "").strip()
        try:
            target = int(line_no)
        except (TypeError, ValueError):
            target = 0

        with self._lock:
            lines = self._read_pool_lines()
            if target <= 0 or target > len(lines):
                return {
                    "ok": False,
                    "code": "mailbox_row_stale",
                    "error": "邮箱列表已变化，请刷新后重试",
                }
            row = lines[target - 1]
            if not hmac.compare_digest(expected_row_id, row_id_from_source(row)):
                return {
                    "ok": False,
                    "code": "mailbox_row_stale",
                    "error": "邮箱列表已变化，请刷新后重试",
                }
            password = password_from_row(row)
            if not password:
                return {
                    "ok": False,
                    "code": "mailbox_password_missing",
                    "error": "这一行没有可复制的密码",
                }
            return {"ok": True, "password": password}

    def reveal_totp(self, row_id: Any, line_no: Any) -> dict[str, Any]:
        expected_row_id = str(row_id or "").strip()
        try:
            target = int(line_no)
        except (TypeError, ValueError):
            target = 0

        with self._lock:
            lines = self._read_pool_lines()
            if target <= 0 or target > len(lines):
                return {
                    "ok": False,
                    "code": "mailbox_row_stale",
                    "error": "邮箱列表已变化，请刷新后重试",
                }
            row = lines[target - 1]
            if not hmac.compare_digest(expected_row_id, row_id_from_source(row)):
                return {
                    "ok": False,
                    "code": "mailbox_row_stale",
                    "error": "邮箱列表已变化，请刷新后重试",
                }
            secret = totp_secret_from_row(row)
            if not secret:
                return {
                    "ok": False,
                    "code": "mailbox_totp_missing",
                    "error": "这一行没有可复制的临时 2FA 验证码",
                }
            now = self.now_fn()
            return {
                "ok": True,
                "kind": "totp",
                "code": generate_totp_code(secret, now=now),
                "remaining": 30 - (int(now) % 30),
            }

    def reveal_mailbox_url(self, row_id: Any, line_no: Any) -> dict[str, Any]:
        expected_row_id = str(row_id or "").strip()
        try:
            target = int(line_no)
        except (TypeError, ValueError):
            target = 0

        with self._lock:
            lines = self._read_pool_lines()
            if target <= 0 or target > len(lines):
                return {
                    "ok": False,
                    "code": "mailbox_row_stale",
                    "error": "邮箱列表已变化，请刷新后重试",
                }
            row = lines[target - 1]
            if not hmac.compare_digest(expected_row_id, row_id_from_source(row)):
                return {
                    "ok": False,
                    "code": "mailbox_row_stale",
                    "error": "邮箱列表已变化，请刷新后重试",
                }
            mailbox_url = mailbox_url_from_row(row)
            if not mailbox_url:
                return {
                    "ok": False,
                    "code": "mailbox_url_missing",
                    "error": "这一行没有取件 URL",
                }
            return {"ok": True, "mailbox_url": mailbox_url}

    def latest_code(self, payload: Any) -> dict[str, Any]:
        value = payload if isinstance(payload, Mapping) else {}
        row, email = self.pool_row_by_line(value.get("line_no"))
        if not row:
            return {"ok": False, "error": "没有找到这一行邮箱"}

        mailbox_url = mailbox_url_from_row(row)
        if mailbox_url:
            try:
                reader = self.mailbox_url_reader_factory(
                    mailbox_url,
                    timeout_seconds=5,
                    proxy="",
                )
                selection = reader.latest_code(include_existing=True)
            except Exception as exc:
                error = self._format_error(exc, self._row_secrets(row))
                return {"ok": False, "error": f"邮箱 URL 查询失败: {error}"}
            code = str(getattr(selection, "code", "") or "")
            return {
                "ok": True,
                "kind": "email",
                "email": email,
                "code": code,
                "message": "已找到最新 OpenAI 邮箱验证码" if code else "未找到新的 OpenAI 邮箱验证码",
            }

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
        config = self._config()
        enabled = config.get("mailbox_result_index_cache") is not False
        return self.result_index.snapshot(results_dir, enabled=enabled).latest_results

    def _latest_sub2_accounts_by_email(self, results_dir: Path) -> dict[str, dict[str, Any]]:
        config = self._config()
        enabled = config.get("mailbox_result_index_cache") is not False
        return self.result_index.snapshot(results_dir, enabled=enabled).latest_sub2_accounts

    def _sub2_status_for(self, account_id: str) -> dict[str, Any]:
        if not account_id:
            return public_sub2_status(None, linked=False)
        if self.sub2_status_lookup is None:
            return public_sub2_status(None, linked=True)
        try:
            status = self.sub2_status_lookup(account_id)
        except Exception:
            status = None
        return public_sub2_status(status, linked=True)

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
                    "batch_id": str(task.get("batch_id") or ""),
                    "batch_started_at": task.get("batch_started_at") or 0,
                    "run_mode": str(task.get("run_mode") or ""),
                }
        return latest

    def list_mailboxes(self) -> dict[str, Any]:
        with self._lock:
            config = self._config()
            pool_path = self._path(config, "pool_path")
            state_path = self._path(config, "state_path")
            results_dir = self._path(config, "results_dir")
            lines = self._read_pool_lines(config)
            import_order = self._reconcile_import_order(lines)
            state = self._read_json_file(state_path)

        latest_batch_by_row = latest_batch_members_by_row(self.run_batch_membership)
        items = state.get("items") if isinstance(state.get("items"), Mapping) else {}
        state_by_line, state_by_email, state_by_row_id = index_mailbox_states(items)

        result_snapshot = self.result_index.snapshot(
            results_dir,
            enabled=config.get("mailbox_result_index_cache") is not False,
        )
        latest_results = result_snapshot.latest_results
        latest_sub2_accounts = result_snapshot.latest_sub2_accounts
        live_progress = self._live_progress_by_email(config)
        rows = []
        counts = {"total": 0, "available": 0, "running": 0, "success": 0, "failed": 0}
        now = self.now_fn()
        for index, row in enumerate(lines, start=1):
            email = email_from_row(row)
            source_row_id = row_id_from_source(row)
            batch_member = latest_batch_by_row.get(source_row_id) or {}
            state_item = indexed_mailbox_state(
                state_by_line,
                state_by_email,
                state_by_row_id,
                row_id=source_row_id,
                email=email,
                line_no=index,
            )
            row_secrets = self._row_secrets(row)
            result = latest_results.get(email) or {}
            sub2_account = latest_sub2_accounts.get(email) or {}
            sub2_account_id = str(sub2_account.get("account_id") or "")
            live_task = live_progress.get(email) or {}
            raw_state_reason = self._format_error(state_item.get("reason") or "", row_secrets)
            state_reason = public_mailbox_reason(raw_state_reason)
            manually_restored = (
                str(state_item.get("status") or "").lower() == "available"
                and str(state_item.get("reason") or "") == "manual_restore"
            )
            if manually_restored:
                result = {}
            result_status = str(result.get("status") or "").lower()
            result_payload = result.get("result") if isinstance(result.get("result"), Mapping) else {}
            failure = public_failure(
                result.get("failure")
                if isinstance(result.get("failure"), Mapping)
                else result_payload.get("failure")
            )
            account_banned = bool(
                result_status == "account_banned"
                or (failure or {}).get("node_code") == "account_banned"
                or str(result_payload.get("status") or "").strip().lower()
                == "account_banned"
            )
            if account_banned:
                # Historical result files can still contain provider details
                # under result.error/local_oauth_exchange_error. They are
                # local diagnostics only and must never be re-exposed by the
                # mailbox row API.
                detail_error = ""
            else:
                detail_error = (
                    (failure or {}).get("technical_summary")
                    or result.get("technical_error")
                    or result_payload.get("local_oauth_exchange_error")
                    or result_payload.get("error")
                    or result.get("error")
                    or ("" if manually_restored else state_reason)
                    or ""
                )
            detail_error = self._format_error(detail_error, row_secrets)
            detail_error = public_mailbox_reason(detail_error)
            failure_message = self._format_error((failure or {}).get("public_message") or "", row_secrets)
            friendly_error = failure_message or friendly_mailbox_error(detail_error)
            phone_risk: Mapping[str, Any] = {}
            if email and self.phone_risk_lookup is not None:
                try:
                    phone_risk = self.phone_risk_lookup(email) or {}
                except Exception:
                    phone_risk = {}
            phone_risk_retry = bool(phone_risk.get("active"))
            phone_risk_label = (
                "手机号风控重试：已启用成熟线路优先"
                if phone_risk_retry
                else ""
            )
            if phone_risk_label:
                friendly_error = (
                    f"{friendly_error}；{phone_risk_label}"
                    if friendly_error
                    else phone_risk_label
                )
            if failure is not None:
                failure = dict(failure)
                failure["public_message"] = failure_message
                failure["technical_summary"] = detail_error
            succeeded = result_status in {"success", "ok", "uploaded"}
            openai_account_id = ""
            if succeeded:
                try:
                    openai_account_id = credentials_from_result(result).account_id
                except OpenAIQuotaError:
                    openai_account_id = ""
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
            timing = (
                (progress or {}).get("timing")
                if isinstance(progress, Mapping)
                else None
            )
            if not isinstance(timing, Mapping):
                timing = (
                    result.get("timing")
                    if isinstance(result.get("timing"), Mapping)
                    else result_payload.get("timing")
                )
            timing = dict(timing) if isinstance(timing, Mapping) else None
            task_status = (
                live_task.get("task_status")
                or batch_member.get("status")
                or result_status
            )
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
            elif count_status == "damaged":
                count_status = "failed"
            counts[count_status] = counts.get(count_status, 0) + 1
            if self.openai_status_lookup is not None:
                sub2_status = resolve_openai_status(
                    self.openai_status_lookup,
                    openai_account_id=openai_account_id,
                    row_id=source_row_id,
                    allow_row_fallback=not manually_restored and (succeeded or status_key == "consumed"),
                )
            else:
                sub2_status = self._sub2_status_for(sub2_account_id)
            sub2_status["summary"] = self._format_error(sub2_status.get("summary") or "", row_secrets)
            quota_status = resolve_quota_status(
                self.openai_quota_status_lookup,
                account_id=openai_account_id,
                row_id=source_row_id,
                allow_row_fallback=not manually_restored and (succeeded or status_key == "consumed"),
            )
            quota_error = self._format_error(quota_status.get("error") or "", row_secrets)
            batch_id, batch_started_at, updated_at = public_batch_metadata(
                live_task,
                batch_member,
                result,
                result_payload,
                state_item,
            )
            rows.append(
                {
                    "line_no": index,
                    "row_id": source_row_id,
                    "email": email,
                    "password": _SECRET_MASK if password_from_row(row) else "",
                    "has_totp": bool(totp_secret_from_row(row)),
                    "has_mailbox_url": bool(mailbox_url_from_row(row)),
                    "phone_risk_retry": phone_risk_retry,
                    "phone_risk_label": phone_risk_label,
                    "status": status_key,
                    "status_label": status_label,
                    "pool_status": state_item.get("status") or "available",
                    "manual_sms_received": manual_sms_received(state_item),
                    "reason": state_reason,
                    "error": friendly_error,
                    "technical_error": detail_error,
                    "failure": failure,
                    "task_id": (
                        live_task.get("task_id")
                        or batch_member.get("task_id")
                        or result.get("task_id")
                        or ""
                    ),
                    "task_status": task_status or result_status,
                    "progress": progress,
                    "timing": timing,
                    "sms_cost_usd": sms_cost_usd,
                    "sms_cost_cny": sms_cost_cny,
                    "sms_exchange_rate": sms_exchange_rate,
                    "sms_exchange_date": sms_exchange_date or "",
                    "batch_id": batch_id,
                    "batch_started_at": batch_started_at,
                    "run_mode": str(
                        live_task.get("run_mode")
                        or result.get("run_mode")
                        or result_payload.get("run_mode")
                        or ""
                    ),
                    "updated_at": updated_at,
                    "source_row": masked_source_row(row),
                    "sub2_status": sub2_status,
                    "quota_status": quota_status.get("status") or "",
                    "quota_error": quota_error,
                    "quota_queried_at": quota_status.get("queried_at"),
                    "quota_5h": quota_status.get("quota_5h"),
                    "quota_7d": quota_status.get("quota_7d"),
                }
            )
        order_entries = import_order.get("entries") if isinstance(import_order.get("entries"), Mapping) else {}
        rows.sort(
            key=lambda item: (
                -int((order_entries.get(str(item.get("row_id") or "")) or {}).get("batch") or 0),
                int((order_entries.get(str(item.get("row_id") or "")) or {}).get("order") or 0),
                int(item.get("line_no") or 0),
            )
        )
        return {
            "ok": True,
            "counts": counts,
            "rows": rows,
            "pool_path": str(pool_path),
            "performance": {"result_index": result_snapshot.metrics},
        }

    def online_mailbox_snapshot(self) -> dict[str, Any]:
        """Return one latest URL mailbox per email without other credentials."""
        with self._lock:
            config = self._config()
            lines = self._read_pool_lines(config)

        latest: dict[str, dict[str, str]] = {}
        skipped = 0
        local_duplicates = 0
        for row in lines:
            email = email_from_row(row)
            mailbox_url = mailbox_url_from_row(row)
            if not email or not mailbox_url:
                skipped += 1
                continue
            if email in latest:
                local_duplicates += 1
                latest.pop(email, None)
            latest[email] = {"email": email, "mailbox_url": mailbox_url}
        return {
            "ok": True,
            "items": list(latest.values()),
            "eligible": len(latest),
            "skipped": skipped,
            "local_duplicates": local_duplicates,
        }

    def _rewrite_state_after_delete(
        self,
        kept_lines: Sequence[str],
        deleted_line_nos: set[int],
        deleted_emails: set[str],
        config: Mapping[str, Any],
    ) -> None:
        rewrite_state_after_delete(self, kept_lines, deleted_line_nos, deleted_emails, config)

    def delete_mailboxes(self, payload: Any) -> dict[str, Any]:
        selected = selected_line_numbers(payload)
        if not selected:
            return {"ok": False, "error": "请先勾选要删除的邮箱"}

        value = payload if isinstance(payload, Mapping) else {}
        requested = value.get("rows")
        bindings: list[tuple[int, str]] = []
        if requested is not None:
            if not isinstance(requested, Sequence) or isinstance(requested, (str, bytes)):
                return {"ok": False, "code": "mailbox_rows_invalid", "error": "删除参数无效"}
            seen_bindings: set[tuple[int, str]] = set()
            for item in requested:
                if not isinstance(item, Mapping):
                    return {"ok": False, "code": "mailbox_rows_invalid", "error": "删除参数无效"}
                try:
                    line_no = int(item.get("line_no") or 0)
                except (TypeError, ValueError):
                    line_no = 0
                row_id = str(item.get("row_id") or "").strip().lower()
                binding = (line_no, row_id)
                if (
                    line_no <= 0
                    or not re.fullmatch(r"[0-9a-f]{64}", row_id)
                    or binding in seen_bindings
                ):
                    return {"ok": False, "code": "mailbox_rows_invalid", "error": "删除参数无效"}
                seen_bindings.add(binding)
                bindings.append(binding)
            if {line_no for line_no, _row_id in bindings} != set(selected):
                return {"ok": False, "code": "mailbox_rows_invalid", "error": "删除参数无效"}

        with self._locked_pool_config() as config:
            lines = self._read_pool_lines(config)
            self._reconcile_import_order(lines)
            for line_no, expected_row_id in bindings:
                if line_no > len(lines) or not hmac.compare_digest(
                    expected_row_id,
                    row_id_from_source(lines[line_no - 1]),
                ):
                    return {
                        "ok": False,
                        "code": "mailbox_rows_stale",
                        "error": "邮箱列表已变化，请刷新后重试",
                    }
            selected_set = set(selected)
            deleted_lines = [line for index, line in enumerate(lines, start=1) if index in selected_set]
            kept_lines = [line for index, line in enumerate(lines, start=1) if index not in selected_set]
            if not deleted_lines:
                return {"ok": False, "error": "选中的邮箱不存在或已经删除"}
            self._write_pool_lines(kept_lines, config)
            self._reconcile_import_order(kept_lines, external_as_new=False)
            if self.next_batch_priority is not None:
                self.next_batch_priority.prune(kept_lines)
            deleted_rows = {
                index: (row_id_from_source(line), email_from_row(line))
                for index, line in enumerate(lines, start=1)
                if index in selected_set
            }
            self._rewrite_state_after_delete(kept_lines, selected_set, deleted_rows, config)

        self._validate_pool()
        self._log(f"邮箱管理删除: {len(deleted_lines)} 条", "warn")
        return {"ok": True, "deleted": len(deleted_lines)}

    def restore_mailboxes(self, payload: Any) -> dict[str, Any]:
        return restore_mailbox_rows(self, payload)

    def resolve_relogin_rows(self, payload: Any) -> dict[str, Any]:
        """Resolve stable 401/404 rows without exposing mailbox credentials."""
        value = payload if isinstance(payload, Mapping) else {}
        requested = value.get("rows")
        if not isinstance(requested, Sequence) or isinstance(requested, (str, bytes)) or not requested:
            return {
                "ok": False,
                "code": "relogin_rows_required",
                "error": "请先勾选需要重登的 401/404 邮箱",
            }
        if len(requested) > 100:
            return {
                "ok": False,
                "code": "relogin_batch_too_large",
                "error": "单批最多重登 100 个邮箱",
            }

        bindings: list[tuple[int, str]] = []
        seen: set[tuple[int, str]] = set()
        for item in requested:
            if not isinstance(item, Mapping):
                return {"ok": False, "code": "relogin_rows_invalid", "error": "重登参数无效"}
            try:
                line_no = int(item.get("line_no") or 0)
            except (TypeError, ValueError):
                line_no = 0
            row_id = str(item.get("row_id") or "").strip().lower()
            binding = (line_no, row_id)
            if line_no <= 0 or not row_id or binding in seen:
                return {"ok": False, "code": "relogin_rows_invalid", "error": "重登参数无效"}
            seen.add(binding)
            bindings.append(binding)

        with self._locked_pool_config() as config:
            lines = self._read_pool_lines(config)
            accounts_by_email = self._latest_sub2_accounts_by_email(
                self._path(config, "results_dir")
            )
            resolved: list[dict[str, Any]] = []
            for line_no, expected_row_id in bindings:
                if line_no > len(lines):
                    return {
                        "ok": False,
                        "code": "mailbox_rows_stale",
                        "error": "邮箱列表已变化，请刷新后重试",
                    }
                source_row = lines[line_no - 1]
                if not hmac.compare_digest(expected_row_id, row_id_from_source(source_row)):
                    return {
                        "ok": False,
                        "code": "mailbox_rows_stale",
                        "error": "邮箱列表已变化，请刷新后重试",
                    }
                email = email_from_row(source_row)
                account = accounts_by_email.get(email) or {}
                account_id = str(account.get("account_id") or "").strip()
                openai_account_id = str(account.get("openai_account_id") or "").strip()
                if not account_id:
                    return {
                        "ok": False,
                        "code": "relogin_sub2_binding_missing",
                        "error": "所选邮箱没有可原位更新的 SUB2 账号",
                    }

                raw_status: Mapping[str, Any] | None = None
                for lookup, lookup_id in (
                    (self.openai_status_lookup, openai_account_id or account_id),
                    (self.sub2_status_lookup, account_id),
                ):
                    if not callable(lookup):
                        continue
                    try:
                        candidate = lookup(lookup_id)
                    except Exception:
                        candidate = None
                    if isinstance(candidate, Mapping) and candidate:
                        raw_status = candidate
                        kind = str(candidate.get("kind") or "").strip().lower()
                        try:
                            code = int(candidate.get("status_code"))
                        except (TypeError, ValueError):
                            code = None
                        if code in {401, 404} or kind in {"unauthorized", "not_found"}:
                            break
                status = public_sub2_status(raw_status, linked=True)
                if not status.get("needs_rerun"):
                    return {
                        "ok": False,
                        "code": "relogin_not_required",
                        "error": "所选邮箱当前不再是 401/404 状态，请刷新后重试",
                    }
                resolved.append(
                    {
                        "row_id": expected_row_id,
                        "line_no": line_no,
                        "email": email,
                        "sub2api_account_id": account_id,
                        "status_code": status.get("status_code"),
                        "status_kind": str(status.get("kind") or "")[:40],
                    }
                )
        return {"ok": True, "items": resolved, "count": len(resolved)}

    def sub2_test(self, payload: Any) -> dict[str, Any]:
        value = payload if isinstance(payload, Mapping) else {}
        row_completed = value.get("_on_row_completed")
        if not callable(row_completed):
            row_completed = None
        requested = value.get("rows")
        if not isinstance(requested, Sequence) or isinstance(requested, (str, bytes)) or not requested:
            return {"ok": False, "code": "sub2_rows_required", "error": "请先勾选要测试的邮箱"}
        bindings: list[tuple[int, str]] = []
        seen: set[tuple[int, str]] = set()
        for item in requested:
            if not isinstance(item, Mapping):
                return {"ok": False, "code": "sub2_rows_invalid", "error": "批量测试参数无效"}
            try:
                line_no = int(item.get("line_no") or 0)
            except (TypeError, ValueError):
                line_no = 0
            row_id = str(item.get("row_id") or "").strip()
            binding = (line_no, row_id)
            if line_no <= 0 or not row_id or binding in seen:
                return {"ok": False, "code": "sub2_rows_invalid", "error": "批量测试参数无效"}
            seen.add(binding)
            bindings.append(binding)

        with self._lock:
            config = self._config()
            lines = self._read_pool_lines(config)
            results_dir = self._path(config, "results_dir")
            resolved: list[dict[str, Any]] = []
            for line_no, expected_row_id in bindings:
                if line_no > len(lines):
                    return {
                        "ok": False,
                        "code": "mailbox_rows_stale",
                        "error": "邮箱列表已变化，请刷新后重试",
                    }
                row = lines[line_no - 1]
                if not hmac.compare_digest(expected_row_id, row_id_from_source(row)):
                    return {
                        "ok": False,
                        "code": "mailbox_rows_stale",
                        "error": "邮箱列表已变化，请刷新后重试",
                    }
                resolved.append(
                    {
                        "row_id": expected_row_id,
                        "line_no": line_no,
                        "email": email_from_row(row),
                    }
                )
            accounts_by_email = self._latest_sub2_accounts_by_email(results_dir)
            for item in resolved:
                account = accounts_by_email.get(item["email"]) or {}
                item["sub2api_account_id"] = str(account.get("account_id") or "")
                if row_completed is not None:
                    item["_on_row_completed"] = row_completed

        if self.sub2_batch_tester is None:
            return {"ok": False, "code": "sub2_not_configured", "error": "SUB2 连接测试尚未配置"}
        try:
            result = self.sub2_batch_tester(resolved)
        except Exception:
            return {"ok": False, "code": "sub2_batch_failed", "error": "SUB2 批量连接测试失败"}
        return dict(result) if isinstance(result, Mapping) else {
            "ok": False,
            "code": "sub2_batch_failed",
            "error": "SUB2 批量连接测试失败",
        }

    def openai_test(self, payload: Any) -> dict[str, Any]:
        """Test successful local OAuth results directly against OpenAI."""
        return run_openai_test(self, payload)

    def selected_success_results(self, payload: Any) -> dict[str, Any]:
        """Resolve stable mailbox selections to local successful result documents."""
        value = payload if isinstance(payload, Mapping) else {}
        with self._lock:
            config = self._config()
            lines = self._read_pool_lines(config)
            internal_rebind = callable(value.get("_on_row_completed")) and value.get("_allow_row_rebind") is True
            if internal_rebind:
                requested = value.get("rows") or ()
                by_row_id = {
                    row_id_from_source(source_row): (line_no, source_row)
                    for line_no, source_row in enumerate(lines, start=1)
                }
                rebound_rows = []
                for item in requested:
                    row_id = str(item.get("row_id") or "").strip() if isinstance(item, Mapping) else ""
                    rebound = by_row_id.get(row_id)
                    if rebound is None:
                        return {"ok": False, "code": "mailbox_rows_stale", "error": "邮箱列表已变化，请刷新后重试"}
                    rebound_rows.append({"row_id": row_id, "line_no": rebound[0], "source_row": rebound[1]})
                resolved = {"ok": True, "rows": rebound_rows}
            else:
                resolved = resolve_source_rows(value, lines, row_id_from_source)
            if not resolved.get("ok"):
                return resolved
            latest = self._latest_results_by_email(self._path(config, "results_dir"))
            items: list[dict[str, Any]] = []
            skipped_items: list[dict[str, Any]] = []
            for selected_row in resolved["rows"]:
                line_no = selected_row["line_no"]
                expected_row_id = selected_row["row_id"]
                source_row = selected_row["source_row"]
                email = email_from_row(source_row)
                document = latest.get(email) or {}
                status = str(document.get("status") or "").strip().lower()
                result_file = Path(str(document.get("_result_file") or ""))
                task_id = str(document.get("task_id") or "").strip()
                if status not in {"success", "ok", "uploaded"} or not task_id or not result_file.is_file():
                    skipped_items.append({"row_id": expected_row_id, "line_no": line_no})
                    continue
                items.append(
                    {
                        "row_id": expected_row_id,
                        "line_no": line_no,
                        "email": email,
                        "task_id": task_id,
                        "result_file": result_file,
                        "document": document,
                    }
                )
        if not items and not (value.get("_include_skipped") is True and skipped_items):
            return {
                "ok": False,
                "code": "mailbox_success_results_required",
                "error": "所选邮箱没有可处理的成功结果",
            }
        return {
            "ok": True,
            "items": items,
            "skipped": len(skipped_items),
            "skipped_items": skipped_items,
        }

    def selected_source_rows(self, payload: Any) -> dict[str, Any]:
        """Return selected source rows only for the explicit credential export route."""
        with self._lock:
            resolved = resolve_source_rows(payload, self._read_pool_lines(), row_id_from_source)
        if not resolved.get("ok"):
            return resolved
        rows = sorted(resolved["rows"], key=lambda item: item["line_no"])
        return {"ok": True, "count": len(rows), "content": "\n".join(item["source_row"] for item in rows)}

    def query_openai_quotas(self, payload: Any) -> dict[str, Any]:
        """Query quota and remove only locally bound HTTP 402 deactivated workspaces."""
        return run_openai_quota_query(self, payload)

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
    "latest_sub2_accounts_by_email",
    "masked_source_row",
    "parse_chatgpt_totp_row",
    "parse_mailbox_url_row",
    "parse_mailbox_password_url_row",
    "parse_oauth_mailbox_row",
    "parse_plain_password_mailbox_row",
    "password_from_row",
    "mailbox_url_from_row",
    "pool_count_status",
    "public_task_account",
    "redact_mailbox_credentials",
    "resolve_config_path",
    "row_id_from_source",
    "selected_line_numbers",
    "sub2_account_id_from_result",
    "public_sub2_status",
    "url_credential_secrets",
]
