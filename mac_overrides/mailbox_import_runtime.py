"""Mailbox source imports and active-run assignment."""

from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any, Mapping, Sequence

try:
    from .chatgpt_totp import mailbox_credential_identity
    from .mailbox_row_formats import (
        is_importable_mailbox_row,
        parse_oauth_mailbox_row,
        row_id_from_source,
    )
except ImportError:  # Loaded as a top-level runtime override.
    from chatgpt_totp import mailbox_credential_identity  # type: ignore[no-redef]
    from mailbox_row_formats import (  # type: ignore[no-redef]
        is_importable_mailbox_row,
        parse_oauth_mailbox_row,
        row_id_from_source,
    )


_IMPORT_ORDER_VERSION = 1
_IMPORT_ORDER_FILE_NAME = "mailbox_import_order.json"


class MailboxImportMixin:
    """Persist imports and hand newly written rows to the active run."""

    def _import_order_path(self) -> Path:
        return Path(self.store.data_dir).resolve() / _IMPORT_ORDER_FILE_NAME

    @staticmethod
    def _write_import_order_file(path: Path, value: Mapping[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.write_text(
            json.dumps(value, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        temporary.chmod(0o600)
        temporary.replace(path)
        path.chmod(0o600)

    def _reconcile_import_order(
        self,
        lines: Sequence[str],
        *,
        external_as_new: bool = True,
    ) -> dict[str, Any]:
        path = self._import_order_path()
        raw = self._read_json_file(path)
        try:
            version = int(raw.get("version") or 0)
        except (TypeError, ValueError):
            version = 0
        valid_store = version == _IMPORT_ORDER_VERSION and isinstance(raw.get("entries"), Mapping)
        try:
            next_batch = max(0, int(raw.get("next_batch") or 0)) if valid_store else 0
        except (TypeError, ValueError):
            next_batch = 0
        entries: dict[str, dict[str, int]] = {}
        if valid_store:
            for raw_row_id, raw_item in raw["entries"].items():
                row_id = str(raw_row_id or "").strip().lower()
                if not re.fullmatch(r"[0-9a-f]{64}", row_id) or not isinstance(raw_item, Mapping):
                    continue
                try:
                    batch = max(0, int(raw_item.get("batch") or 0))
                    order = max(0, int(raw_item.get("order") or 0))
                except (TypeError, ValueError):
                    continue
                entries[row_id] = {"batch": batch, "order": order}
                next_batch = max(next_batch, batch)

        row_ids = [row_id_from_source(line) for line in lines]
        current = set(row_ids)
        entries = {row_id: item for row_id, item in entries.items() if row_id in current}
        missing = [row_id for row_id in row_ids if row_id not in entries]
        if missing:
            batch = next_batch + 1 if valid_store and external_as_new else 0
            if batch:
                next_batch = batch
            for order, row_id in enumerate(missing):
                entries[row_id] = {"batch": batch, "order": order}

        reconciled = {
            "version": _IMPORT_ORDER_VERSION,
            "next_batch": next_batch,
            "entries": entries,
        }
        if reconciled != raw:
            self._write_import_order_file(path, reconciled)
        return reconciled

    def _append_import_order_batch(
        self,
        state: Mapping[str, Any],
        appended: Sequence[str],
    ) -> dict[str, Any]:
        next_batch = max(0, int(state.get("next_batch") or 0)) + 1
        entries = {
            str(row_id): dict(item)
            for row_id, item in (state.get("entries") or {}).items()
            if isinstance(item, Mapping)
        }
        for order, line in enumerate(appended):
            entries[row_id_from_source(line)] = {"batch": next_batch, "order": order}
        value = {"version": _IMPORT_ORDER_VERSION, "next_batch": next_batch, "entries": entries}
        self._write_import_order_file(self._import_order_path(), value)
        return value

    def import_mailboxes(self, content: Any) -> dict[str, Any]:
        new_lines = [
            line.strip()
            for line in str(content or "").splitlines()
            if is_importable_mailbox_row(line)
        ]
        if not new_lines:
            return {"ok": False, "error": "请粘贴要导入的邮箱"}

        # Query the importer before taking the source flock to preserve the
        # established importer-lock -> source-flock lock order.
        run_active = False
        if callable(self.runtime_status):
            try:
                runtime = self.runtime_status(self._config())
                run_active = bool(runtime.get("running") if isinstance(runtime, Mapping) else False)
            except Exception:
                run_active = False

        with self._locked_pool_config() as config:
            old_lines = self._read_pool_lines(config)
            import_order = self._reconcile_import_order(old_lines)
            seen = {
                mailbox_credential_identity(line, parse_oauth_mailbox_row)
                for line in old_lines
            }
            appended: list[str] = []
            skipped = 0
            for line in new_lines:
                identity = mailbox_credential_identity(line, parse_oauth_mailbox_row)
                if identity in seen:
                    skipped += 1
                    continue
                seen.add(identity)
                appended.append(line)
            if not appended:
                return {"ok": False, "error": "没有新增邮箱，可能都是重复行"}
            self._write_pool_lines(old_lines + appended, config)
            self._append_import_order_batch(import_order, appended)
        if callable(self.runtime_status):
            try:
                runtime = self.runtime_status(self._config())
                run_active = run_active or bool(
                    runtime.get("running") if isinstance(runtime, Mapping) else False
                )
            except Exception:
                pass

        append_result: dict[str, Any] = {}
        if run_active:
            append_result.update(joined_current_batch=0, queued_current_batch=0, next_batch=len(appended))
        if callable(self.current_run_append):
            try:
                observed = self.current_run_append(tuple(appended))
                if isinstance(observed, Mapping):
                    for key in ("joined_current_batch", "queued_current_batch", "next_batch"):
                        append_result[key] = max(int(observed.get(key) or 0), 0)
                    reason = str(observed.get("append_reason") or "").strip()
                    if reason:
                        append_result["append_reason"] = reason
                    for key in ("append_node_code", "append_node_label"):
                        value = str(observed.get(key) or "").strip()
                        if value:
                            append_result[key] = value
                    if run_active and not any(
                        append_result.get(key)
                        for key in ("joined_current_batch", "queued_current_batch", "next_batch")
                    ):
                        append_result["next_batch"] = len(appended)
                        append_result["append_node_code"] = "current_batch_closed"
                        append_result["append_node_label"] = "追加当前运行批次"
                        append_result["append_reason"] = (
                            "导入期间当前批次已结束，新增邮箱已转入下一批优先队列"
                        )
            except Exception as exc:
                if run_active:
                    append_result.update(
                        joined_current_batch=0,
                        queued_current_batch=0,
                        next_batch=len(appended),
                        append_node_code="current_batch_append_failed",
                        append_node_label="追加当前运行批次",
                        append_reason=f"当前批次追加失败（{type(exc).__name__}），已转入下一批",
                    )
        if append_result.get("next_batch") and self.next_batch_priority is not None:
            self.next_batch_priority.mark_imported(appended)
        check = self._validate_pool()
        self._log(f"邮箱管理追加导入: 新增 {len(appended)} 条，跳过重复 {skipped} 条", "success")
        return {
            "ok": True,
            "imported": len(appended),
            "skipped": skipped,
            "validate": check,
            **append_result,
        }


__all__ = ["MailboxImportMixin"]
