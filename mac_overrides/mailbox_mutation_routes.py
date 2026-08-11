"""HTTP controllers for mailbox-pool mutations.

Mailbox imports are deliberately acknowledged after the source mutation, not
after a synchronous enrichment of every mailbox result.  The dashboard can
refresh that read model independently, so a busy importer cannot keep the
operator's import dialog spinning after the write has completed.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Any, Callable

try:
    from .mailbox_source_lock import MailboxSourceLockTimeout
    from .mailbox_state_runtime import (
        mark_mailboxes_draft,
        mark_mailboxes_manual_used,
        mark_mailboxes_unavailable,
        restore_manual_used_mailboxes,
        restore_draft_mailboxes,
    )
except ImportError:  # Loaded as top-level modules by the macOS launcher.
    from mailbox_source_lock import MailboxSourceLockTimeout
    from mailbox_state_runtime import (
        mark_mailboxes_draft,
        mark_mailboxes_manual_used,
        mark_mailboxes_unavailable,
        restore_manual_used_mailboxes,
        restore_draft_mailboxes,
    )


class MailboxMutationRouteController:
    """Keep mutation response policy out of the Flask route assembly module."""

    def __init__(
        self,
        *,
        module: Any,
        mailbox_admin: Any,
        public_state: Callable[[], Mapping[str, Any]],
        logs: Any,
        safe_error: Callable[[Any], str] = str,
        draft_action: Callable[[Any, Mapping[str, Any]], Mapping[str, Any]] = mark_mailboxes_draft,
        draft_restore_action: Callable[[Any, Mapping[str, Any]], Mapping[str, Any]] = restore_draft_mailboxes,
        unavailable_action: Callable[[Any, Mapping[str, Any]], Mapping[str, Any]] = mark_mailboxes_unavailable,
        manual_used_action: Callable[[Any, Mapping[str, Any]], Mapping[str, Any]] = mark_mailboxes_manual_used,
        manual_unused_action: Callable[[Any, Mapping[str, Any]], Mapping[str, Any]] = restore_manual_used_mailboxes,
    ) -> None:
        self.module = module
        self.mailbox_admin = mailbox_admin
        self.public_state = public_state
        self.logs = logs
        self.safe_error = safe_error
        self.draft_action = draft_action
        self.draft_restore_action = draft_restore_action
        self.unavailable_action = unavailable_action
        self.manual_used_action = manual_used_action
        self.manual_unused_action = manual_unused_action

    def import_mailboxes(self):
        data, error = self._request_data()
        if error is not None:
            return error
        return self._mutate(
            "导入",
            lambda payload: self.mailbox_admin.import_mailboxes(
                payload.get("pool_content", "")
            ),
            data,
            refresh=False,
            include_state=False,
        )

    def delete_mailboxes(self):
        return self._run_payload_mutation("删除", self.mailbox_admin.delete_mailboxes)

    def restore_mailboxes(self):
        return self._run_payload_mutation("放回可领取", self.mailbox_admin.restore_mailboxes)

    def unavailable_mailboxes(self):
        return self._run_payload_mutation(
            "设置不可用",
            lambda payload: self.unavailable_action(self.mailbox_admin, payload),
        )

    def draft_mailboxes(self):
        return self._run_payload_mutation(
            "放入草稿箱",
            lambda payload: self.draft_action(self.mailbox_admin, payload),
        )

    def restore_draft_mailboxes(self):
        return self._run_payload_mutation(
            "草稿放回可用",
            lambda payload: self.draft_restore_action(self.mailbox_admin, payload),
        )

    def manual_used_mailboxes(self):
        return self._run_payload_mutation(
            "标记已手动接码",
            lambda payload: self.manual_used_action(self.mailbox_admin, payload),
        )

    def manual_unused_mailboxes(self):
        return self._run_payload_mutation(
            "标记未用",
            lambda payload: self.manual_unused_action(self.mailbox_admin, payload),
        )

    def source_export(self):
        data, error = self._request_data()
        if error is not None:
            return error
        try:
            result = self.mailbox_admin.selected_source_rows(data)
            if not isinstance(result, Mapping):
                raise TypeError("invalid source export response")
            response = dict(result)
            if not response.get("ok"):
                return self.module.jsonify(response), self._result_status(response)
            response["filename"] = f"mailboxes-original-{datetime.now().strftime('%Y%m%d-%H%M%S')}.txt"
            return self.module.jsonify(response)
        except MailboxSourceLockTimeout as exc:
            return self.module.jsonify(
                ok=False,
                code=exc.code,
                error_code=exc.code,
                node_code=exc.node_code,
                node_label=exc.node_label,
                error=exc.public_message,
            ), exc.status_code
        except Exception as exc:
            self.logs.add(f"邮箱原格式导出失败: {type(exc).__name__}", "error")
            return self.module.jsonify(
                ok=False,
                code="mailbox_source_export_failed",
                error="邮箱原格式导出失败：服务未返回有效结果",
            ), 500

    def routes(self) -> tuple[tuple[str, str, Callable[..., Any], list[str]], ...]:
        return (
            ("/api/mailboxes/import", "api_mailboxes_import", self.import_mailboxes, ["POST"]),
            ("/api/mailboxes/delete", "api_mailboxes_delete", self.delete_mailboxes, ["POST"]),
            ("/api/mailboxes/restore", "api_mailboxes_restore", self.restore_mailboxes, ["POST"]),
            ("/api/mailboxes/unavailable", "api_mailboxes_unavailable", self.unavailable_mailboxes, ["POST"]),
            ("/api/mailboxes/draft", "api_mailboxes_draft", self.draft_mailboxes, ["POST"]),
            (
                "/api/mailboxes/draft/restore",
                "api_mailboxes_draft_restore",
                self.restore_draft_mailboxes,
                ["POST"],
            ),
            (
                "/api/mailboxes/manual-used",
                "api_mailboxes_manual_used",
                self.manual_used_mailboxes,
                ["POST"],
            ),
            (
                "/api/mailboxes/manual-unused",
                "api_mailboxes_manual_unused",
                self.manual_unused_mailboxes,
                ["POST"],
            ),
            (
                "/api/mailboxes/source-export",
                "api_mailboxes_source_export",
                self.source_export,
                ["POST"],
            ),
        )

    def _run_payload_mutation(
        self,
        operation: str,
        action: Callable[[dict[str, Any]], Mapping[str, Any]],
    ):
        data, error = self._request_data()
        if error is not None:
            return error
        return self._mutate(operation, action, data)

    def _request_data(self) -> tuple[dict[str, Any], Any | None]:
        data = self.module.request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return {}, (
                self.module.jsonify(ok=False, error="请求必须是 JSON 对象"),
                400,
            )
        return data, None

    def _mutate(
        self,
        operation: str,
        action: Callable[[dict[str, Any]], Mapping[str, Any]],
        data: dict[str, Any],
        *,
        refresh: bool = True,
        include_state: bool = True,
    ):
        try:
            result = action(data)
            if not isinstance(result, Mapping):
                return self.module.jsonify(
                    ok=False,
                    code="mailbox_mutation_invalid_response",
                    error=f"邮箱管理{operation}失败：服务未返回有效结果",
                ), 502
            response = dict(result)
            if not response.get("ok"):
                return self.module.jsonify(response), self._result_status(response)

            # Import acknowledgement must not wait on importer-owned locks or
            # scan thousands of historical result files.  The UI refreshes the
            # read model immediately after the request settles.
            if refresh:
                try:
                    response["mailboxes"] = self.mailbox_admin.list_mailboxes()
                except MailboxSourceLockTimeout as exc:
                    response["mailboxes_refresh_required"] = True
                    response["mailboxes_refresh_error"] = exc.public_message
                except Exception as exc:
                    response["mailboxes_refresh_required"] = True
                    self._log_refresh_failure(operation, exc)
            else:
                response["mailboxes_refresh_required"] = True
            if include_state:
                try:
                    response["state"] = self.public_state()
                except Exception as exc:
                    response["state_refresh_required"] = True
                    self._log_refresh_failure("状态同步", exc)
            return self.module.jsonify(response)
        except MailboxSourceLockTimeout as exc:
            return self.module.jsonify(
                ok=False,
                code=exc.code,
                error_code=exc.code,
                node_code=exc.node_code,
                node_label=exc.node_label,
                error=exc.public_message,
            ), exc.status_code
        except Exception as exc:
            safe = self.safe_error(exc)
            self.logs.add(f"邮箱管理{operation}失败: {safe}", "error")
            return self.module.jsonify(
                ok=False,
                code="mailbox_mutation_failed",
                error=f"邮箱管理{operation}失败: {safe}",
            ), 500

    def _log_refresh_failure(self, operation: str, exc: Exception) -> None:
        try:
            safe = self.safe_error(exc)
        except Exception:
            safe = type(exc).__name__
        self.logs.add(f"邮箱管理{operation}后刷新列表失败: {safe}", "warn")

    @staticmethod
    def _result_status(result: Mapping[str, Any]) -> int:
        code = str(result.get("code") or result.get("error_code") or "")
        if code in {
            "mailbox_rows_stale",
            "mailbox_rows_running",
            "mailbox_rows_not_available",
            "mailbox_rows_not_draft",
            "mailbox_rows_not_manual_used",
            "mailbox_source_lock_timeout",
        }:
            return 409
        if code.startswith("mailbox_source_lock"):
            return 409
        return 400


__all__ = ["MailboxMutationRouteController"]
