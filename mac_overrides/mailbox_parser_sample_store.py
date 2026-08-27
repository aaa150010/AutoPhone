"""Local, access-controlled snapshots for mailbox parser misses.

This store is intentionally separate from the diagnostic index and business
results.  Parser samples are a narrowly scoped exception: their raw URL and
response bodies are retained locally so a new parser strategy can be designed
from the exact provider payload that was not understood.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import base64
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import threading
import uuid
from typing import Any


SCHEMA_VERSION = 1
MAILBOX_PARSER_REVISION = "pickup-dynamic-v6-samples"
DEFAULT_RETENTION_DAYS = 30
DEFAULT_MAX_SAMPLES = 5000
DEFAULT_MAX_BYTES = 512 * 1024 * 1024
MAX_SAMPLE_BYTES = 16 * 1024 * 1024
MAX_ARTIFACT_BYTES = 2 * 1024 * 1024
SAMPLE_STATUSES = frozenset({"new", "in_review", "resolved", "ignored"})


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _text(value: Any, limit: int = 500) -> str:
    return str(value or "")[:limit]


def _id(value: Any, limit: int = 160) -> str:
    return "".join(character for character in str(value or "")[:limit] if character.isalnum() or character in "._:-")


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _mapping(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


def _body_bytes(value: Any) -> bytes:
    if isinstance(value, bytes):
        return value[:MAX_ARTIFACT_BYTES]
    if isinstance(value, bytearray):
        return bytes(value[:MAX_ARTIFACT_BYTES])
    return str(value or "").encode("utf-8", "replace")[:MAX_ARTIFACT_BYTES]


def _raw_body_bytes(value: Any) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    return str(value or "").encode("utf-8", "replace")


def _decode_body(body: bytes, content_type: str = "") -> tuple[str, str]:
    charset = "utf-8"
    marker = str(content_type or "")
    for token in marker.split(";")[1:]:
        key, _, value = token.partition("=")
        if key.strip().lower() == "charset" and value.strip():
            charset = value.strip().strip('"')[:40]
            break
    try:
        return body.decode(charset, "replace"), charset
    except (LookupError, UnicodeError):
        return body.decode("utf-8", "replace"), "utf-8"


def _redacted_export_text(value: Any, limit: int = 1200) -> str:
    """Keep sanitized exports useful without copying credentials or OTPs."""
    import re
    text = str(value or "")[:limit]
    text = re.sub(r"(?i)(https?://)([^\s/@:]+):([^\s/@]+)@", r"\1<credential>@", text)
    text = re.sub(r"(?i)([?&](?:auth_code|code|key|token|access_token|refresh_token|id_token|email|phone)=[^&\s]+)", "<query-redacted>", text)
    text = re.sub(r"(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{6,}", "<credential>", text)
    text = re.sub(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", "<email>", text)
    text = re.sub(r"(?<!\d)\d{6}(?!\d)", "<otp>", text)
    return text


class MailboxParserSampleStore:
    """Thread-safe SQLite store with bounded raw response artifacts."""

    def __init__(
        self,
        data_dir: str | Path,
        *,
        retention_days: int = DEFAULT_RETENTION_DAYS,
        max_samples: int = DEFAULT_MAX_SAMPLES,
        max_bytes: int = DEFAULT_MAX_BYTES,
    ) -> None:
        self.root = Path(data_dir).expanduser().resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.root, 0o700)
        except OSError:
            pass
        self.path = self.root / "samples.sqlite3"
        self.retention_days = max(1, int(retention_days))
        self.max_samples = max(1, int(max_samples))
        self.max_bytes = max(1, int(max_bytes))
        self._lock = threading.RLock()
        self._write_failures = 0
        self._discarded = 0
        self._initialize()

    @contextmanager
    def _connection(self):
        connection = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=10000")
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA journal_mode=WAL")
        try:
            yield connection
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._lock, self._connection() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS mailbox_parser_samples (
                    sample_id TEXT PRIMARY KEY,
                    dedup_key TEXT NOT NULL UNIQUE,
                    scope TEXT NOT NULL,
                    chain TEXT NOT NULL,
                    workflow TEXT NOT NULL,
                    driver TEXT NOT NULL,
                    task_id TEXT NOT NULL,
                    batch_id TEXT NOT NULL,
                    stage TEXT NOT NULL,
                    incident_id TEXT NOT NULL,
                    mailbox_url TEXT NOT NULL,
                    final_url TEXT NOT NULL,
                    url_fingerprint TEXT NOT NULL,
                    response_fingerprint TEXT NOT NULL,
                    parser_version TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    diagnostics_json TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'new',
                    first_seen_at TEXT NOT NULL,
                    last_seen_at TEXT NOT NULL,
                    occurrence_count INTEGER NOT NULL DEFAULT 1,
                    response_count INTEGER NOT NULL DEFAULT 0,
                    total_bytes INTEGER NOT NULL DEFAULT 0,
                    truncated INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS mailbox_parser_sample_responses (
                    response_id TEXT PRIMARY KEY,
                    sample_id TEXT NOT NULL REFERENCES mailbox_parser_samples(sample_id) ON DELETE CASCADE,
                    response_fingerprint TEXT NOT NULL,
                    request_role TEXT NOT NULL,
                    request_url TEXT NOT NULL,
                    response_url TEXT NOT NULL,
                    http_status INTEGER,
                    content_type TEXT NOT NULL,
                    charset TEXT NOT NULL,
                    body BLOB NOT NULL,
                    body_bytes INTEGER NOT NULL,
                    first_seen_at TEXT NOT NULL,
                    last_seen_at TEXT NOT NULL,
                    occurrence_count INTEGER NOT NULL DEFAULT 1,
                    UNIQUE(sample_id, response_fingerprint)
                );
                CREATE INDEX IF NOT EXISTS idx_mailbox_parser_samples_last_seen
                    ON mailbox_parser_samples(last_seen_at DESC);
                CREATE INDEX IF NOT EXISTS idx_mailbox_parser_samples_scope_status
                    ON mailbox_parser_samples(scope, status, last_seen_at DESC);
                CREATE INDEX IF NOT EXISTS idx_mailbox_parser_samples_host
                    ON mailbox_parser_samples(final_url);
                """
            )
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass

    @staticmethod
    def _row(row: sqlite3.Row | None) -> dict[str, Any] | None:
        if row is None:
            return None
        result = dict(row)
        try:
            result["diagnostics"] = json.loads(result.pop("diagnostics_json") or "{}")
        except (TypeError, ValueError, json.JSONDecodeError):
            result["diagnostics"] = {}
        for key in ("truncated",):
            result[key] = bool(result.get(key))
        return result

    @staticmethod
    def _response_row(row: sqlite3.Row, *, include_body: bool = False) -> dict[str, Any]:
        result = dict(row)
        body = bytes(result.pop("body", b"") or b"")
        result["body_bytes"] = int(result.get("body_bytes") or len(body))
        result["body_fingerprint"] = hashlib.sha256(body).hexdigest()
        if include_body:
            result["body_base64"] = base64.b64encode(body).decode("ascii")
            text, charset = _decode_body(body, str(result.get("content_type") or ""))
            result["body_text"] = text
            result["charset"] = charset
        return result

    def record_failure(self, sample: Mapping[str, Any], responses: Sequence[Mapping[str, Any]]) -> str:
        """Append or update one deduplicated parser-miss sample."""
        now = _now()
        raw_url = _text(sample.get("mailbox_url"), 4096)
        if not raw_url:
            return ""
        scope = _id(sample.get("scope") or "ordinary", 32)
        stage = _id(sample.get("stage") or "email_code_waiting", 100)
        parser_version = _id(sample.get("parser_version") or "unknown", 120)
        url_fingerprint = hashlib.sha256(raw_url.encode("utf-8", "replace")).hexdigest()
        dedup_key = hashlib.sha256(
            "|".join((scope, url_fingerprint, stage, parser_version)).encode("utf-8")
        ).hexdigest()
        prepared: list[dict[str, Any]] = []
        total_bytes = 0
        truncated = False
        for item in responses:
            if not isinstance(item, Mapping):
                continue
            source_body = _raw_body_bytes(item.get("body"))
            remaining = max(0, MAX_SAMPLE_BYTES - total_bytes)
            if bool(item.get("truncated")) or len(source_body) > MAX_ARTIFACT_BYTES or len(source_body) > remaining:
                truncated = True
            body = source_body[: min(MAX_ARTIFACT_BYTES, remaining)]
            if not body:
                continue
            body_fingerprint = hashlib.sha256(body).hexdigest()
            request_url = _text(item.get("request_url") or raw_url, 4096)
            response_url = _text(item.get("response_url") or item.get("url") or raw_url, 4096)
            artifact_fingerprint = hashlib.sha256(
                "|".join((
                    _id(item.get("request_role") or "request", 40),
                    request_url,
                    response_url,
                    body_fingerprint,
                )).encode("utf-8", "replace")
            ).hexdigest()
            text, charset = _decode_body(body, str(item.get("content_type") or ""))
            prepared.append({
                "response_fingerprint": artifact_fingerprint,
                "body_fingerprint": body_fingerprint,
                "request_role": _id(item.get("request_role") or "request", 40),
                "request_url": request_url,
                "response_url": response_url,
                "http_status": int(item.get("status")) if isinstance(item.get("status"), int) else None,
                "content_type": _text(item.get("content_type"), 180),
                "charset": charset,
                "body": body,
                "body_bytes": len(body),
                "body_text": text,
            })
            total_bytes += len(body)
        if not prepared:
            self._discarded += 1
            return ""
        response_fingerprint = prepared[-1]["response_fingerprint"]
        final_url = prepared[-1]["response_url"]
        sample_id = "MPS-" + uuid.uuid4().hex[:16].upper()
        diagnostics = _mapping(sample.get("diagnostics"))
        try:
            with self._lock, self._connection() as db:
                db.execute("BEGIN IMMEDIATE")
                existing = db.execute(
                    "SELECT sample_id FROM mailbox_parser_samples WHERE dedup_key=?",
                    (dedup_key,),
                ).fetchone()
                if existing:
                    sample_id = str(existing[0])
                    db.execute(
                        "UPDATE mailbox_parser_samples SET final_url=?, response_fingerprint=?, reason=?, diagnostics_json=?, last_seen_at=?, occurrence_count=occurrence_count+1, total_bytes=total_bytes+? WHERE sample_id=?",
                        (final_url, response_fingerprint, _text(sample.get("reason"), 160), _json(diagnostics), now, total_bytes, sample_id),
                    )
                else:
                    db.execute(
                        "INSERT INTO mailbox_parser_samples (sample_id,dedup_key,scope,chain,workflow,driver,task_id,batch_id,stage,incident_id,mailbox_url,final_url,url_fingerprint,response_fingerprint,parser_version,reason,diagnostics_json,status,first_seen_at,last_seen_at,occurrence_count,response_count,total_bytes,truncated) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'new',?,?,1,0,?,0)",
                        (
                            sample_id, dedup_key, scope, _id(sample.get("chain") or "ordinary", 48),
                            _id(sample.get("workflow") or "run", 64), _id(sample.get("driver") or "unknown", 48),
                            _id(sample.get("task_id"), 180), _id(sample.get("batch_id"), 180), stage,
                            _id(sample.get("incident_id"), 64), raw_url, final_url, url_fingerprint,
                            response_fingerprint, parser_version, _text(sample.get("reason"), 160), _json(diagnostics),
                            now, now, total_bytes,
                        ),
                    )
                for item in prepared:
                    duplicate = db.execute(
                        "SELECT response_id FROM mailbox_parser_sample_responses WHERE sample_id=? AND response_fingerprint=?",
                        (sample_id, item["response_fingerprint"]),
                    ).fetchone()
                    if duplicate:
                        db.execute(
                            "UPDATE mailbox_parser_sample_responses SET last_seen_at=?, occurrence_count=occurrence_count+1, request_role=?, request_url=?, response_url=?, http_status=?, content_type=?, charset=?, body=?, body_bytes=? WHERE response_id=?",
                            (now, item["request_role"], item["request_url"], item["response_url"], item["http_status"], item["content_type"], item["charset"], item["body"], item["body_bytes"], str(duplicate[0])),
                        )
                    else:
                        db.execute(
                            "INSERT INTO mailbox_parser_sample_responses (response_id,sample_id,response_fingerprint,request_role,request_url,response_url,http_status,content_type,charset,body,body_bytes,first_seen_at,last_seen_at,occurrence_count) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,1)",
                            (uuid.uuid4().hex, sample_id, item["response_fingerprint"], item["request_role"], item["request_url"], item["response_url"], item["http_status"], item["content_type"], item["charset"], item["body"], item["body_bytes"], now, now),
                        )
                count = int(db.execute("SELECT COUNT(*) FROM mailbox_parser_sample_responses WHERE sample_id=?", (sample_id,)).fetchone()[0])
                retained_bytes = int(db.execute("SELECT COALESCE(SUM(body_bytes),0) FROM mailbox_parser_sample_responses WHERE sample_id=?", (sample_id,)).fetchone()[0] or 0)
                db.execute("UPDATE mailbox_parser_samples SET response_count=?, total_bytes=?, truncated=CASE WHEN ? THEN 1 ELSE truncated END WHERE sample_id=?", (count, retained_bytes, int(truncated), sample_id))
                db.execute("COMMIT")
        except Exception:
            self._write_failures += 1
            return ""
        self.cleanup()
        return sample_id

    def attach_incident(self, sample_id: str, incident_id: str) -> None:
        if not sample_id or not incident_id:
            return
        with self._lock, self._connection() as db:
            db.execute("UPDATE mailbox_parser_samples SET incident_id=? WHERE sample_id=? AND (incident_id='' OR incident_id IS NULL)", (_id(incident_id, 64), _id(sample_id, 80)))

    def list(self, query: Mapping[str, Any] | None = None) -> list[dict[str, Any]]:
        query = query or {}
        clauses, params = self._where(query)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        try:
            limit = max(1, min(10000, int(query.get("limit") or 100)))
        except (TypeError, ValueError):
            limit = 100
        try:
            offset = max(0, int(query.get("offset") or 0))
        except (TypeError, ValueError):
            offset = 0
        with self._lock, self._connection() as db:
            rows = db.execute(f"SELECT * FROM mailbox_parser_samples{where} ORDER BY last_seen_at DESC LIMIT ? OFFSET ?", (*params, limit, offset)).fetchall()
            total = int(db.execute(f"SELECT COUNT(*) FROM mailbox_parser_samples{where}", params).fetchone()[0])
        result = [self._row(row) for row in rows]
        return [{**(item or {}), "total": total} for item in result]

    @staticmethod
    def _where(query: Mapping[str, Any]) -> tuple[list[str], list[Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        for key in ("scope", "status", "chain", "workflow", "driver", "reason", "stage"):
            value = _text(query.get(key), 120)
            if value:
                clauses.append(f"{key}=?")
                params.append(value)
        keyword = _text(query.get("q"), 180)
        if keyword:
            clauses.append("(sample_id LIKE ? OR final_url LIKE ? OR task_id LIKE ? OR batch_id LIKE ? OR reason LIKE ?)")
            params.extend([f"%{keyword}%"] * 5)
        return clauses, params

    def count(self, query: Mapping[str, Any] | None = None) -> int:
        clauses, params = self._where(query or {})
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        with self._lock, self._connection() as db:
            return int(db.execute(f"SELECT COUNT(*) FROM mailbox_parser_samples{where}", params).fetchone()[0])

    def get(self, sample_id: str, *, include_responses: bool = False, include_body: bool = False) -> dict[str, Any] | None:
        sample_id = _id(sample_id, 80)
        with self._lock, self._connection() as db:
            row = db.execute("SELECT * FROM mailbox_parser_samples WHERE sample_id=?", (sample_id,)).fetchone()
            result = self._row(row)
            if result is None:
                return None
            if include_responses:
                responses = db.execute("SELECT * FROM mailbox_parser_sample_responses WHERE sample_id=? ORDER BY first_seen_at ASC", (sample_id,)).fetchall()
                result["responses"] = [self._response_row(item, include_body=include_body) for item in responses]
            return result

    def update_status(self, sample_ids: Sequence[str], status: str) -> int:
        normalized = [(_id(value, 80)) for value in sample_ids if _id(value, 80)]
        if status not in SAMPLE_STATUSES or not normalized:
            return 0
        with self._lock, self._connection() as db:
            marks = ",".join("?" for _ in normalized)
            cursor = db.execute(f"UPDATE mailbox_parser_samples SET status=? WHERE sample_id IN ({marks})", (status, *normalized))
            return int(cursor.rowcount or 0)

    def delete(self, sample_ids: Sequence[str]) -> int:
        normalized = [(_id(value, 80)) for value in sample_ids if _id(value, 80)]
        if not normalized:
            return 0
        with self._lock, self._connection() as db:
            marks = ",".join("?" for _ in normalized)
            cursor = db.execute(f"DELETE FROM mailbox_parser_samples WHERE sample_id IN ({marks})", normalized)
            return int(cursor.rowcount or 0)

    def cleanup(self) -> int:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=self.retention_days)).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        deleted = 0
        with self._lock, self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            old = db.execute("SELECT sample_id FROM mailbox_parser_samples WHERE last_seen_at<?", (cutoff,)).fetchall()
            for row in old:
                db.execute("DELETE FROM mailbox_parser_samples WHERE sample_id=?", (row[0],))
            deleted += len(old)
            rows = db.execute("SELECT sample_id FROM mailbox_parser_samples ORDER BY last_seen_at DESC").fetchall()
            for row in rows[self.max_samples:]:
                db.execute("DELETE FROM mailbox_parser_samples WHERE sample_id=?", (row[0],))
                deleted += 1
            total = int(db.execute("SELECT COALESCE(SUM(body_bytes),0) FROM mailbox_parser_sample_responses").fetchone()[0] or 0)
            if total > self.max_bytes:
                for row in db.execute("SELECT sample_id FROM mailbox_parser_samples WHERE status IN ('resolved','ignored') ORDER BY last_seen_at ASC").fetchall():
                    if total <= self.max_bytes:
                        break
                    bytes_for_sample = int(db.execute("SELECT COALESCE(SUM(body_bytes),0) FROM mailbox_parser_sample_responses WHERE sample_id=?", (row[0],)).fetchone()[0] or 0)
                    db.execute("DELETE FROM mailbox_parser_samples WHERE sample_id=?", (row[0],))
                    total -= bytes_for_sample
                    deleted += 1
            if total > self.max_bytes:
                for row in db.execute("SELECT sample_id FROM mailbox_parser_samples ORDER BY last_seen_at ASC").fetchall():
                    if total <= self.max_bytes:
                        break
                    bytes_for_sample = int(db.execute("SELECT COALESCE(SUM(body_bytes),0) FROM mailbox_parser_sample_responses WHERE sample_id=?", (row[0],)).fetchone()[0] or 0)
                    db.execute("DELETE FROM mailbox_parser_samples WHERE sample_id=?", (row[0],))
                    total -= bytes_for_sample
                    deleted += 1
            db.execute("COMMIT")
        return deleted

    def export(self, sample_id: str, *, fixture: bool = False) -> dict[str, Any] | None:
        result = self.get(sample_id, include_responses=True, include_body=fixture)
        if result is None:
            return None
        if fixture:
            return result
        sanitized = {key: value for key, value in result.items() if key not in {"mailbox_url", "final_url", "responses"}}
        sanitized["responses"] = []
        for response in result.get("responses") or []:
            safe_response = {
                key: value
                for key, value in response.items()
                if key not in {"request_url", "response_url", "body_base64", "body_text"}
            }
            safe_response["body_text"] = _redacted_export_text(response.get("body_text"), limit=MAX_ARTIFACT_BYTES)
            sanitized["responses"].append(safe_response)
        return sanitized

    def health(self) -> dict[str, Any]:
        with self._lock, self._connection() as db:
            samples = int(db.execute("SELECT COUNT(*) FROM mailbox_parser_samples").fetchone()[0])
            responses = int(db.execute("SELECT COUNT(*) FROM mailbox_parser_sample_responses").fetchone()[0])
            bytes_total = int(db.execute("SELECT COALESCE(SUM(body_bytes),0) FROM mailbox_parser_sample_responses").fetchone()[0] or 0)
        try:
            database_bytes = self.path.stat().st_size
        except OSError:
            database_bytes = 0
        return {
            "ok": True,
            "schema_version": SCHEMA_VERSION,
            "samples": samples,
            "responses": responses,
            "bytes": bytes_total,
            "database_bytes": database_bytes,
            "retention_days": self.retention_days,
            "max_samples": self.max_samples,
            "max_bytes": self.max_bytes,
            "write_failures": self._write_failures,
            "discarded": self._discarded,
            "storage_status": "ok",
            "path": str(self.path.name),
        }


_STORES: dict[str, MailboxParserSampleStore] = {}
_DIAGNOSTIC_STORE: Any | None = None


def configure_sample_stores(*, ordinary: MailboxParserSampleStore | None = None, free: MailboxParserSampleStore | None = None, diagnostic_store: Any | None = None) -> None:
    if ordinary is not None:
        _STORES["ordinary"] = ordinary
    if free is not None:
        _STORES["free"] = free
    global _DIAGNOSTIC_STORE
    _DIAGNOSTIC_STORE = diagnostic_store


def sample_store_for(scope: str = "ordinary") -> MailboxParserSampleStore | None:
    return _STORES.get(str(scope or "ordinary").strip().lower())


def record_parser_failure(sample: Mapping[str, Any], responses: Sequence[Mapping[str, Any]]) -> str:
    store = sample_store_for(str(sample.get("scope") or "ordinary"))
    if store is None:
        return ""
    sample_id = store.record_failure(sample, responses)
    if sample_id and _DIAGNOSTIC_STORE is not None:
        try:
            incident_id = _DIAGNOSTIC_STORE.record({
                "chain": sample.get("chain") or "ordinary",
                "workflow": sample.get("workflow") or "run",
                "driver": sample.get("driver") or "unknown",
                "task_id": sample.get("task_id") or "",
                "batch_id": sample.get("batch_id") or "",
                "subject_kind": "mailbox_parser_sample",
                "subject_ref": sample_id,
                "stage_group": sample.get("stage") or "email_code_waiting",
                "node_code": "mailbox_parser_unmatched",
                "node_label": "邮箱解析未识别",
                "outcome": "error",
                "message": "邮箱响应已保存到解析样本库，等待增加解析策略",
                "failure": {
                    "error_code": "mailbox_parser_unmatched",
                    "retryable": True,
                    "sample_id": sample_id,
                    "reason": _text(sample.get("reason"), 160),
                },
            })
            store.attach_incident(sample_id, incident_id)
        except Exception:
            pass
    return sample_id


def record_client_parser_failure(client: Any, sample: Mapping[str, Any]) -> str:
    artifacts = tuple(getattr(client, "sample_artifacts", lambda: ())() or ())
    return record_parser_failure(sample, artifacts)


__all__ = [
    "MailboxParserSampleStore",
    "MAILBOX_PARSER_REVISION",
    "MAX_ARTIFACT_BYTES",
    "MAX_SAMPLE_BYTES",
    "SAMPLE_STATUSES",
    "configure_sample_stores",
    "record_parser_failure",
    "record_client_parser_failure",
    "sample_store_for",
]
