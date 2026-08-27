"""Local routes for inspecting and replaying mailbox parser samples."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import base64
import hashlib
import ipaddress
import json
from typing import Any

try:
    from .mailbox_url_runtime import parse_mailbox_payload
    from .mailbox_parser_sample_store import MAILBOX_PARSER_REVISION
except ImportError:  # pragma: no cover
    from mailbox_url_runtime import parse_mailbox_payload  # type: ignore[no-redef]
    from mailbox_parser_sample_store import MAILBOX_PARSER_REVISION  # type: ignore[no-redef]


class MailboxParserSampleRouteController:
    def __init__(self, *, module: Any, ordinary_store: Any | None, free_store: Any | None) -> None:
        self.module = module
        self.stores = {
            "ordinary": ordinary_store,
            "free": free_store,
        }

    def _store(self, scope: str) -> Any | None:
        return self.stores.get(str(scope or "").strip().lower())

    def _stores_for(self, scope: str = "") -> list[tuple[str, Any]]:
        normalized = str(scope or "").strip().lower()
        if normalized in self.stores:
            store = self._store(normalized)
            return [(normalized, store)] if store is not None else []
        return [(name, store) for name, store in self.stores.items() if store is not None]

    @staticmethod
    def _loopback(request: Any) -> bool:
        host = str(getattr(request, "remote_addr", "") or "").strip().lower()
        if host == "localhost":
            return True
        try:
            return bool(host) and ipaddress.ip_address(host).is_loopback
        except ValueError:
            return False

    @staticmethod
    def _ids(data: Any) -> list[str]:
        values = data.get("sample_ids") if isinstance(data, Mapping) else []
        if isinstance(values, str):
            values = [values]
        if not isinstance(values, Sequence):
            return []
        return [str(value or "").strip()[:80] for value in values if str(value or "").strip()]

    def _find(self, sample_id: str, scope: str = "") -> tuple[str, Any, dict[str, Any]] | None:
        for name, store in self._stores_for(scope):
            result = store.get(sample_id, include_responses=True)
            if result is not None:
                return name, store, result
        return None

    def list(self):
        args = self.module.request.args
        query = {key: args.get(key, "") for key in ("scope", "status", "chain", "workflow", "driver", "reason", "stage", "q", "limit", "offset")}
        rows: list[dict[str, Any]] = []
        total = 0
        try:
            limit = max(1, min(200, int(query.get("limit") or 100)))
        except (TypeError, ValueError):
            limit = 100
        try:
            offset = max(0, int(query.get("offset") or 0))
        except (TypeError, ValueError):
            offset = 0
        fetch_query = dict(query)
        fetch_query.update({"offset": 0, "limit": min(10000, offset + limit)})
        for scope, store in self._stores_for(query.get("scope", "")):
            values = store.list(fetch_query)
            total += int(store.count(query))
            for row in values:
                row = dict(row)
                row.pop("total", None)
                row["scope"] = row.get("scope") or scope
                # Never expose raw URL fields in list responses.
                row.pop("mailbox_url", None)
                row.pop("final_url", None)
                rows.append(row)
        rows.sort(key=lambda row: str(row.get("last_seen_at") or ""), reverse=True)
        return self.module.jsonify(
            ok=True,
            samples=rows[offset:offset + limit],
            total=total,
            offset=offset,
            limit=limit,
            health={scope: store.health() for scope, store in self._stores_for(query.get("scope", ""))},
        )

    def detail(self, sample_id: str):
        found = self._find(sample_id, self.module.request.args.get("scope", ""))
        if found is None:
            return self.module.jsonify(ok=False, error="解析样本不存在", code="mailbox_parser_sample_not_found"), 404
        scope, _store, result = found
        result = dict(result)
        result["scope"] = scope
        result.pop("mailbox_url", None)
        result.pop("final_url", None)
        for response in result.get("responses") or []:
            response.pop("request_url", None)
            response.pop("response_url", None)
            response.pop("body_base64", None)
            response.pop("body_text", None)
        return self.module.jsonify(ok=True, sample=result)

    def reveal(self, sample_id: str):
        request = self.module.request
        if not self._loopback(request):
            return self.module.jsonify(ok=False, error="原始样本仅允许本机查看", code="mailbox_parser_sample_loopback_only"), 403
        confirmation = request.get_json(silent=True) or {}
        if not isinstance(confirmation, Mapping) or confirmation.get("confirm_raw") is not True:
            return self.module.jsonify(ok=False, error="查看原始样本需要显式确认", code="mailbox_parser_sample_confirmation_required"), 400
        found = self._find(sample_id, request.args.get("scope", ""))
        if found is None:
            return self.module.jsonify(ok=False, error="解析样本不存在", code="mailbox_parser_sample_not_found"), 404
        scope, store, _unused = found
        result = store.get(sample_id, include_responses=True, include_body=True)
        return self.module.jsonify(ok=True, scope=scope, sample=result, raw_access=True)

    def reparse(self, sample_id: str):
        found = self._find(sample_id, self.module.request.args.get("scope", ""))
        if found is None:
            return self.module.jsonify(ok=False, error="解析样本不存在", code="mailbox_parser_sample_not_found"), 404
        scope, store, _unused = found
        full = store.get(sample_id, include_responses=True, include_body=True) or {}
        messages: list[Any] = []
        detail_url_fingerprints: list[str] = []
        parse_errors: list[str] = []
        for response in full.get("responses") or []:
            try:
                raw = base64.b64decode(str(response.get("body_base64") or ""), validate=False).decode(str(response.get("charset") or "utf-8"), "replace")
                parsed, links = parse_mailbox_payload(raw, str(response.get("response_url") or full.get("mailbox_url") or ""))
                messages.extend(parsed)
                detail_url_fingerprints.extend(hashlib.sha256(str(link).encode("utf-8", "replace")).hexdigest() for link in links)
            except Exception as exc:
                parse_errors.append(type(exc).__name__)
        code_count = sum(1 for message in messages if str(getattr(message, "code", "") or ""))
        return self.module.jsonify(
            ok=True,
            sample_id=sample_id,
            scope=scope,
            parser_version=MAILBOX_PARSER_REVISION,
            reparse={
                "message_count": len(messages),
                "code_message_count": code_count,
                "detail_url_fingerprints": list(dict.fromkeys(detail_url_fingerprints)),
                "parse_errors": parse_errors,
                "messages": [
                    {
                        "code_present": bool(getattr(message, "code", "")),
                        "code_source": str(getattr(message, "code_source", "") or ""),
                        "field_sources": list(getattr(message, "field_sources", ()) or ()),
                        "received_at": str(getattr(message, "received_at", "") or ""),
                    }
                    for message in messages
                ],
            },
        )

    def status(self):
        data = self.module.request.get_json(silent=True) or {}
        status = str(data.get("status") or "").strip().lower() if isinstance(data, Mapping) else ""
        if status not in {"new", "in_review", "resolved", "ignored"}:
            return self.module.jsonify(ok=False, error="样本状态无效", code="mailbox_parser_sample_status_invalid"), 400
        ids = self._ids(data)
        if not ids:
            return self.module.jsonify(ok=False, error="未提供解析样本 ID", code="mailbox_parser_sample_ids_required"), 400
        total = 0
        for scope, store in self._stores_for(data.get("scope", "") if isinstance(data, Mapping) else ""):
            total += store.update_status(ids, status)
        return self.module.jsonify(ok=True, updated=total, status=status)

    def delete(self):
        data = self.module.request.get_json(silent=True) or {}
        ids = self._ids(data)
        if not ids:
            return self.module.jsonify(ok=False, error="未提供解析样本 ID", code="mailbox_parser_sample_ids_required"), 400
        total = 0
        for scope, store in self._stores_for(data.get("scope", "") if isinstance(data, Mapping) else ""):
            total += store.delete(ids)
        return self.module.jsonify(ok=True, deleted=total)

    def cleanup(self):
        total = sum(store.cleanup() for _scope, store in self._stores_for())
        return self.module.jsonify(ok=True, deleted=total, health={scope: store.health() for scope, store in self._stores_for()})

    def export(self):
        request = self.module.request
        data = request.get_json(silent=True) or {}
        sample_id = str(data.get("sample_id") or "").strip() if isinstance(data, Mapping) else ""
        fixture = str(data.get("format") or "sanitized").strip().lower() == "fixture" if isinstance(data, Mapping) else False
        if fixture:
            if not self._loopback(request):
                return self.module.jsonify(ok=False, error="原始夹具仅允许本机导出", code="mailbox_parser_sample_loopback_only"), 403
            if not isinstance(data, Mapping) or data.get("confirm_raw") is not True:
                return self.module.jsonify(ok=False, error="导出原始夹具需要显式确认", code="mailbox_parser_sample_confirmation_required"), 400
        found = self._find(sample_id, data.get("scope", "") if isinstance(data, Mapping) else "")
        if found is None:
            return self.module.jsonify(ok=False, error="解析样本不存在", code="mailbox_parser_sample_not_found"), 404
        scope, store, _unused = found
        payload = store.export(sample_id, fixture=fixture)
        if payload is None:
            return self.module.jsonify(ok=False, error="解析样本导出失败", code="mailbox_parser_sample_export_failed"), 500
        return self.module.jsonify(ok=True, scope=scope, format="fixture" if fixture else "sanitized", content=json.dumps(payload, ensure_ascii=False, indent=2), redaction_applied=not fixture)

    def health(self):
        return self.module.jsonify(ok=True, health={scope: store.health() for scope, store in self._stores_for()})


__all__ = ["MailboxParserSampleRouteController"]
