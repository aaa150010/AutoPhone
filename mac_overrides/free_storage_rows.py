"""Row projections and bounded pagination shared by all domains for the Free SQLite store.

Split out of ``free_storage.py``; ``FreeSQLiteStore`` composes these domain
mixins so the class body stays navigable while the on-disk schema, method set
and behavior remain unchanged.  Mixins rely on attributes defined by the
schema band (``self._dir``, ``self._db_path``, ``self._lock``, ``self._connection``,
``self._transaction`` ...).
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Mapping, Sequence
from urllib.parse import urlsplit

try:
    from .free_storage_common import (
    MANAGER_OWNER_KEY,
    MANAGER_OWNER_TTL_SECONDS,
    MIGRATION_KEY,
    PROXY_REPAIR_KEY,
    SCHEMA_VERSION,
    SECRET_MASK,
    TERMINAL_TASK_STATUSES,
    FreeStorageError,
    LeaseConflict,
    ManagerOwnerConflict,
    RevisionConflict,
    _EMAIL_RE,
    _LEGACY_PLAIN_DIMENSION_KEYS,
    _LEGACY_PROXY_DIMENSION_KEYS,
    _MAILBOX_SPLIT_RE,
    _MISSING,
    _NON_SECRET_METADATA_KEYS,
    _NON_SECRET_METADATA_KEY_TOKENS,
    _PRIVATE_KEYS,
    _SENSITIVE_KEY_RE,
    _clear_legacy_pool_dimensions,
    _fingerprint,
    _is_private_key,
    _json_object,
    _legacy_proxy_url,
    _mask_email,
    _mask_proxy,
    _merge_private_payload,
    _migration_marker_version,
    _normalize_proxy,
    _now,
    _parse_mailbox_line,
    _partition_json,
    _payload_with_fields,
    _redact,
    _safe_float,
    _safe_json,
    _split_private_payload,
    _stored_bool,
    _valid_migration_marker,
    )
except ImportError:  # macOS launcher imports overrides as top-level modules.
    from free_storage_common import (  # type: ignore[no-redef]
    MANAGER_OWNER_KEY,
    MANAGER_OWNER_TTL_SECONDS,
    MIGRATION_KEY,
    PROXY_REPAIR_KEY,
    SCHEMA_VERSION,
    SECRET_MASK,
    TERMINAL_TASK_STATUSES,
    FreeStorageError,
    LeaseConflict,
    ManagerOwnerConflict,
    RevisionConflict,
    _EMAIL_RE,
    _LEGACY_PLAIN_DIMENSION_KEYS,
    _LEGACY_PROXY_DIMENSION_KEYS,
    _MAILBOX_SPLIT_RE,
    _MISSING,
    _NON_SECRET_METADATA_KEYS,
    _NON_SECRET_METADATA_KEY_TOKENS,
    _PRIVATE_KEYS,
    _SENSITIVE_KEY_RE,
    _clear_legacy_pool_dimensions,
    _fingerprint,
    _is_private_key,
    _json_object,
    _legacy_proxy_url,
    _mask_email,
    _mask_proxy,
    _merge_private_payload,
    _migration_marker_version,
    _normalize_proxy,
    _now,
    _parse_mailbox_line,
    _partition_json,
    _payload_with_fields,
    _redact,
    _safe_float,
    _safe_json,
    _split_private_payload,
    _stored_bool,
    _valid_migration_marker,
    )


class FreeStorageRowMixin:
    """Methods moved verbatim from FreeSQLiteStore."""


    @staticmethod
    def _row_payload(row: sqlite3.Row, *, include_private: bool = True) -> dict[str, Any]:
        try:
            payload = _json_object(json.loads(str(row["payload"] or "{}")))
        except (TypeError, ValueError, json.JSONDecodeError):
            payload = {}
        if include_private:
            try:
                private_payload = _json_object(
                    json.loads(str(row["private_payload"] or "{}"))
                ) if "private_payload" in row.keys() else {}
            except (TypeError, ValueError, json.JSONDecodeError):
                private_payload = {}
            merged = _merge_private_payload(payload, private_payload)
            return _json_object(merged)
        return _redact(payload)

    @staticmethod
    def _mailbox_dict(row: sqlite3.Row, *, public: bool = False) -> dict[str, Any]:
        payload = FreeStorageRowMixin._row_payload(row, include_private=not public)
        if public:
            payload = _redact(payload)
        result = {
            "row_id": str(row["row_id"]),
            "email": str(row["email"]) if not public else _mask_email(row["email"]),
            "status": str(row["status"]),
            "batch_id": str(row["batch_id"]),
            "revision": int(row["revision"] or 0),
            "created_at": str(row["created_at"]),
            "updated_at": str(row["updated_at"]),
            "lease_owner": str(row["lease_owner"]) if not public else (SECRET_MASK if row["lease_owner"] else ""),
            "lease_until": row["lease_until"],
            "payload": payload,
        }
        if public:
            result.update({
                "email_masked": _mask_email(row["email"]),
                "subject_ref_fingerprint": _fingerprint(row["email"]),
                "has_mailbox_url": bool(row["mailbox_url"]),
                "mailbox_url": SECRET_MASK if row["mailbox_url"] else "",
            })
        else:
            result["mailbox_url"] = str(row["mailbox_url"])
        return result

    @staticmethod
    def _proxy_dict(row: sqlite3.Row, *, public: bool = False) -> dict[str, Any]:
        payload = FreeStorageRowMixin._row_payload(row, include_private=not public)
        result = {
            "proxy_id": str(row["proxy_id"]),
            "scheme": str(row["scheme"]),
            "status": str(row["status"]),
            "enabled": bool(row["enabled"]),
            "revision": int(row["revision"] or 0),
            "created_at": str(row["created_at"]),
            "updated_at": str(row["updated_at"]),
            "lease_owner": str(row["lease_owner"]) if not public else (SECRET_MASK if row["lease_owner"] else ""),
            "lease_until": row["lease_until"],
            "payload": _redact(payload) if public else payload,
        }
        result["proxy"] = _mask_proxy(row["proxy"]) if public else str(row["proxy"])
        return result

    @staticmethod
    def _task_dict(row: sqlite3.Row, *, public: bool = False) -> dict[str, Any]:
        payload = FreeStorageRowMixin._row_payload(row, include_private=not public)
        result = {
            "task_id": str(row["task_id"]),
            "status": str(row["status"]),
            "revision": int(row["revision"] or 0),
            "created_at": str(row["created_at"]),
            "updated_at": str(row["updated_at"]),
            "lease_owner": str(row["lease_owner"]) if not public else (SECRET_MASK if row["lease_owner"] else ""),
            "lease_until": row["lease_until"],
            "payload": _redact(payload) if public else payload,
        }
        return result

    @staticmethod
    def _result_dict(row: sqlite3.Row, *, public: bool = False) -> dict[str, Any]:
        payload = FreeStorageRowMixin._row_payload(row, include_private=not public)
        return {
            "row_id": str(row["row_id"]),
            "created_at": str(row["created_at"]),
            "updated_at": str(row["updated_at"]),
            "payload": _redact(payload) if public else payload,
        }

    @staticmethod
    def _remail_order_dict(row: sqlite3.Row, *, public: bool = False) -> dict[str, Any]:
        payload = FreeStorageRowMixin._row_payload(row, include_private=not public)
        if public:
            payload = _redact(payload)
        return {
            "order_no": str(row["order_no"]),
            "status": str(row["status"]),
            "delivery_email": str(row["delivery_email"]) if not public else _mask_email(row["delivery_email"]),
            "delivery_email_masked": _mask_email(row["delivery_email"]),
            "imported": bool(row["imported"]),
            "pool_row_id": str(row["pool_row_id"]),
            "created_at": str(row["created_at"]),
            "updated_at": str(row["updated_at"]),
            "payload": payload,
        }

    def _page(
        self,
        table: str,
        *,
        status: str | None,
        limit: int,
        offset: int,
        public: bool,
    ) -> dict[str, Any]:
        converters = {
            "mailboxes": self._mailbox_dict,
            "proxies": self._proxy_dict,
            "tasks": self._task_dict,
        }
        converter = converters.get(table)
        if converter is None:
            raise ValueError("不支持的 Free 分页资源")
        page_limit = max(1, min(5_000, int(limit)))
        page_offset = max(0, int(offset))
        clauses = ["1=1"]
        params: list[Any] = []
        if status:
            clauses.append("status=?")
            params.append(str(status))
        where = " AND ".join(clauses)
        with self._connection() as db:
            summary = db.execute(
                f"SELECT COUNT(*) AS total,COALESCE(MAX(updated_at),'') AS latest FROM {table} WHERE {where}",
                params,
            ).fetchone()
            rows = db.execute(
                f"SELECT * FROM {table} WHERE {where} ORDER BY updated_at DESC,rowid DESC LIMIT ? OFFSET ?",
                [*params, page_limit, page_offset],
            ).fetchall()
        total = int(summary["total"] or 0) if summary is not None else 0
        latest = str(summary["latest"] or "") if summary is not None else ""
        return {
            "items": [converter(row, public=public) for row in rows],
            "total": total,
            "offset": page_offset,
            "limit": page_limit,
            "revision": f"{total}:{latest}",
        }


__all__ = [
    "FreeStorageRowMixin",
]
