from __future__ import annotations

from collections.abc import Mapping
from contextlib import contextmanager
from datetime import timedelta
from functools import wraps
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import threading
import time
from typing import Any
import urllib.parse

from flask import Flask, jsonify, redirect, render_template, request, session, url_for
from werkzeug.exceptions import RequestEntityTooLarge

from security import token_hash, verify_password


PREFIX = "/token-tool"
MANAGER_PREFIX = f"{PREFIX}/mailboxes"
API_PREFIX = f"{PREFIX}/api"
_EMAIL_RE = re.compile(
    r"(?i)^[a-z0-9][a-z0-9._%+-]*@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$"
)
_BATCH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SOURCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
_LOGIN_WINDOW_SECONDS = 15 * 60
_LOGIN_MAX_FAILURES = 5


SCHEMA = """
CREATE TABLE IF NOT EXISTS mailboxes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    email_key TEXT NOT NULL UNIQUE,
    current_url TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'available' CHECK (status = 'available'),
    first_uploaded_at TEXT NOT NULL,
    last_uploaded_at TEXT NOT NULL,
    upload_count INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS upload_batches (
    batch_id TEXT PRIMARY KEY,
    request_digest TEXT NOT NULL,
    source TEXT NOT NULL,
    received_at TEXT NOT NULL,
    submitted INTEGER NOT NULL,
    created INTEGER NOT NULL,
    updated INTEGER NOT NULL,
    duplicates INTEGER NOT NULL,
    rejected INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS upload_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_id TEXT NOT NULL,
    email TEXT NOT NULL,
    email_key TEXT NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('created', 'updated', 'duplicate')),
    previous_url TEXT,
    submitted_url TEXT NOT NULL,
    uploaded_at TEXT NOT NULL,
    FOREIGN KEY (batch_id) REFERENCES upload_batches(batch_id)
);
CREATE INDEX IF NOT EXISTS idx_mailboxes_last_uploaded ON mailboxes(last_uploaded_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_upload_events_uploaded ON upload_events(uploaded_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_upload_events_email ON upload_events(email_key, id DESC);
"""


class BatchConflict(RuntimeError):
    pass


def _utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _safe_int(value: Any, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return max(minimum, min(parsed, maximum))


def _escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _normalized_item(value: Any) -> dict[str, str] | None:
    if not isinstance(value, Mapping):
        return None
    email = str(value.get("email") or "").strip().lower()
    mailbox_url = str(value.get("mailbox_url") or "").strip()
    if not _EMAIL_RE.fullmatch(email) or not mailbox_url or len(mailbox_url) > 4096:
        return None
    try:
        parsed = urllib.parse.urlsplit(mailbox_url)
    except ValueError:
        return None
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        return None
    return {"email": email, "mailbox_url": mailbox_url}


@contextmanager
def _database(app: Flask):
    connection = sqlite3.connect(app.config["DATABASE_PATH"], timeout=30)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 30000")
    try:
        yield connection
    finally:
        connection.close()


def init_database(app: Flask) -> None:
    database_path = Path(app.config["DATABASE_PATH"])
    database_path.parent.mkdir(parents=True, exist_ok=True)
    with _database(app) as connection:
        connection.execute("PRAGMA journal_mode = WAL")
        connection.executescript(SCHEMA)
        connection.commit()


def _batch_summary(row: Mapping[str, Any], *, idempotent: bool = False) -> dict[str, Any]:
    return {
        "ok": True,
        "batch_id": str(row["batch_id"]),
        "submitted": int(row["submitted"]),
        "created": int(row["created"]),
        "updated": int(row["updated"]),
        "duplicates": int(row["duplicates"]),
        "rejected": int(row["rejected"]),
        "idempotent": idempotent,
    }


def import_batch(
    app: Flask,
    *,
    batch_id: str,
    source: str,
    raw_items: list[Any],
) -> dict[str, Any]:
    digest = hashlib.sha256(
        json.dumps(
            {"source": source, "items": raw_items},
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    items = []
    rejected = 0
    for raw in raw_items:
        item = _normalized_item(raw)
        if item is None:
            rejected += 1
        else:
            items.append(item)
    if not items:
        raise ValueError("没有有效邮箱")

    timestamp = _utc_now()
    with _database(app) as connection:
        connection.execute("BEGIN IMMEDIATE")
        existing_batch = connection.execute(
            "SELECT * FROM upload_batches WHERE batch_id = ?",
            (batch_id,),
        ).fetchone()
        if existing_batch is not None:
            if not hmac.compare_digest(str(existing_batch["request_digest"]), digest):
                connection.rollback()
                raise BatchConflict("批次编号已用于其他数据")
            connection.commit()
            return _batch_summary(existing_batch, idempotent=True)

        connection.execute(
            """
            INSERT INTO upload_batches (
                batch_id, request_digest, source, received_at,
                submitted, created, updated, duplicates, rejected
            ) VALUES (?, ?, ?, ?, ?, 0, 0, 0, ?)
            """,
            (batch_id, digest, source, timestamp, len(raw_items), rejected),
        )
        created = 0
        updated = 0
        duplicates = 0
        for item in items:
            current = connection.execute(
                "SELECT * FROM mailboxes WHERE email_key = ?",
                (item["email"],),
            ).fetchone()
            if current is None:
                action = "created"
                previous_url = None
                created += 1
                connection.execute(
                    """
                    INSERT INTO mailboxes (
                        email, email_key, current_url, status,
                        first_uploaded_at, last_uploaded_at, upload_count
                    ) VALUES (?, ?, ?, 'available', ?, ?, 1)
                    """,
                    (item["email"], item["email"], item["mailbox_url"], timestamp, timestamp),
                )
            elif hmac.compare_digest(str(current["current_url"]), item["mailbox_url"]):
                action = "duplicate"
                previous_url = str(current["current_url"])
                duplicates += 1
                connection.execute(
                    """
                    UPDATE mailboxes
                    SET last_uploaded_at = ?, upload_count = upload_count + 1
                    WHERE email_key = ?
                    """,
                    (timestamp, item["email"]),
                )
            else:
                action = "updated"
                previous_url = str(current["current_url"])
                updated += 1
                connection.execute(
                    """
                    UPDATE mailboxes
                    SET email = ?, current_url = ?, status = 'available',
                        last_uploaded_at = ?, upload_count = upload_count + 1
                    WHERE email_key = ?
                    """,
                    (item["email"], item["mailbox_url"], timestamp, item["email"]),
                )
            connection.execute(
                """
                INSERT INTO upload_events (
                    batch_id, email, email_key, action,
                    previous_url, submitted_url, uploaded_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    batch_id,
                    item["email"],
                    item["email"],
                    action,
                    previous_url,
                    item["mailbox_url"],
                    timestamp,
                ),
            )
        connection.execute(
            """
            UPDATE upload_batches
            SET created = ?, updated = ?, duplicates = ?
            WHERE batch_id = ?
            """,
            (created, updated, duplicates, batch_id),
        )
        connection.commit()
    return {
        "ok": True,
        "batch_id": batch_id,
        "submitted": len(raw_items),
        "created": created,
        "updated": updated,
        "duplicates": duplicates,
        "rejected": rejected,
        "idempotent": False,
    }


def create_app(test_config: Mapping[str, Any] | None = None) -> Flask:
    app = Flask(
        __name__,
        static_folder="static",
        static_url_path=f"{MANAGER_PREFIX}/static",
        template_folder="templates",
    )
    app.config.update(
        DATABASE_PATH=os.environ.get("DATABASE_PATH", "/data/mailboxes.db"),
        WEB_PASSWORD_HASH=os.environ.get("WEB_PASSWORD_HASH", ""),
        API_TOKEN_SHA256=os.environ.get("API_TOKEN_SHA256", ""),
        SECRET_KEY=os.environ.get("SESSION_SECRET", ""),
        MAX_CONTENT_LENGTH=8 * 1024 * 1024,
        MAX_IMPORT_ITEMS=_safe_int(os.environ.get("MAX_IMPORT_ITEMS"), 10_000, 1, 10_000),
        PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_SAMESITE="Strict",
        SESSION_COOKIE_PATH=PREFIX,
    )
    if test_config:
        app.config.update(dict(test_config))
    if not app.config.get("SECRET_KEY"):
        raise RuntimeError("SESSION_SECRET is required")
    if not app.config.get("WEB_PASSWORD_HASH"):
        raise RuntimeError("WEB_PASSWORD_HASH is required")
    if not re.fullmatch(r"[0-9a-f]{64}", str(app.config.get("API_TOKEN_SHA256") or "")):
        raise RuntimeError("API_TOKEN_SHA256 is required")

    app.extensions["login_failures"] = {}
    app.extensions["login_failures_lock"] = threading.Lock()
    init_database(app)

    def csrf_token() -> str:
        value = session.get("csrf_token")
        if not value:
            value = secrets.token_urlsafe(24)
            session["csrf_token"] = value
        return str(value)

    def valid_csrf(value: Any) -> bool:
        expected = str(session.get("csrf_token") or "")
        provided = str(value or "")
        return bool(expected and provided and hmac.compare_digest(expected, provided))

    def signed_in() -> bool:
        return bool(session.get("online_mailbox_authenticated"))

    def manager_required(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if not signed_in():
                if request.path.startswith(API_PREFIX):
                    return jsonify(ok=False, error="登录已失效"), 401
                return redirect(url_for("login"))
            return view(*args, **kwargs)

        return wrapped

    def api_authorized() -> bool:
        authorization = str(request.headers.get("Authorization") or "")
        if not authorization.startswith("Bearer "):
            return False
        supplied = authorization[7:].strip()
        if not supplied:
            return False
        return hmac.compare_digest(token_hash(supplied), app.config["API_TOKEN_SHA256"])

    def login_blocked(remote: str) -> bool:
        now = time.monotonic()
        with app.extensions["login_failures_lock"]:
            rows = [
                value
                for value in app.extensions["login_failures"].get(remote, [])
                if now - value < _LOGIN_WINDOW_SECONDS
            ]
            app.extensions["login_failures"][remote] = rows
            return len(rows) >= _LOGIN_MAX_FAILURES

    def record_login_failure(remote: str) -> None:
        with app.extensions["login_failures_lock"]:
            app.extensions["login_failures"].setdefault(remote, []).append(time.monotonic())

    @app.after_request
    def security_headers(response):
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; "
            "base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
        )
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.errorhandler(RequestEntityTooLarge)
    def too_large(_error):
        return jsonify(ok=False, error="请求数据超过 8 MB 限制"), 413

    @app.get(f"{API_PREFIX}/health")
    def health():
        return jsonify(ok=True, service="token-tool-mailboxes")

    @app.route(MANAGER_PREFIX)
    def manager_root():
        return redirect(f"{MANAGER_PREFIX}/", code=308)

    @app.route(f"{MANAGER_PREFIX}/login", methods=["GET", "POST"])
    def login():
        if signed_in():
            return redirect(f"{MANAGER_PREFIX}/")
        error = ""
        remote = str(request.remote_addr or "unknown")
        if request.method == "POST":
            if login_blocked(remote):
                error = "登录尝试过多，请 15 分钟后重试"
            elif not valid_csrf(request.form.get("csrf_token")):
                error = "登录页面已失效，请刷新后重试"
            elif verify_password(str(request.form.get("password") or ""), app.config["WEB_PASSWORD_HASH"]):
                session.clear()
                session["online_mailbox_authenticated"] = True
                session["csrf_token"] = secrets.token_urlsafe(24)
                session.permanent = True
                with app.extensions["login_failures_lock"]:
                    app.extensions["login_failures"].pop(remote, None)
                return redirect(f"{MANAGER_PREFIX}/")
            else:
                record_login_failure(remote)
                error = "访问密码不正确"
        return render_template("login.html", csrf_token=csrf_token(), error=error)

    @app.post(f"{MANAGER_PREFIX}/logout")
    @manager_required
    def logout():
        if not valid_csrf(request.form.get("csrf_token")):
            return "Bad Request", 400
        session.clear()
        return redirect(url_for("login"))

    @app.get(f"{MANAGER_PREFIX}/")
    @manager_required
    def manager():
        return render_template("mailboxes.html", csrf_token=csrf_token())

    @app.post(f"{API_PREFIX}/mailboxes/import")
    def api_import_mailboxes():
        if not api_authorized():
            return jsonify(ok=False, error="API 密钥无效"), 401
        body = request.get_json(silent=True)
        if not isinstance(body, Mapping):
            return jsonify(ok=False, error="请求必须是 JSON 对象"), 400
        batch_id = str(body.get("batch_id") or "").strip()
        source = str(body.get("source") or "autophone").strip().lower()
        raw_items = body.get("items")
        if not _BATCH_RE.fullmatch(batch_id):
            return jsonify(ok=False, error="批次编号无效"), 400
        if not _SOURCE_RE.fullmatch(source):
            source = "unknown"
        if not isinstance(raw_items, list):
            return jsonify(ok=False, error="items 必须是数组"), 400
        if len(raw_items) > app.config["MAX_IMPORT_ITEMS"]:
            return jsonify(ok=False, error="邮箱数量超过单次上传限制"), 413
        try:
            result = import_batch(
                app,
                batch_id=batch_id,
                source=source,
                raw_items=raw_items,
            )
        except BatchConflict:
            return jsonify(ok=False, error="批次编号已用于其他数据"), 409
        except ValueError:
            return jsonify(ok=False, error="没有有效邮箱"), 400
        return jsonify(result)

    @app.get(f"{API_PREFIX}/mailboxes")
    @manager_required
    def api_mailboxes():
        page = _safe_int(request.args.get("page"), 1, 1, 1_000_000)
        page_size = _safe_int(request.args.get("page_size"), 50, 1, 100)
        search = str(request.args.get("search") or "").strip().lower()[:200]
        where = ""
        params: list[Any] = []
        if search:
            where = "WHERE email_key LIKE ? ESCAPE '\\'"
            params.append(f"%{_escape_like(search)}%")
        with _database(app) as connection:
            total = int(connection.execute(
                f"SELECT COUNT(*) FROM mailboxes {where}",
                params,
            ).fetchone()[0])
            rows = connection.execute(
                f"""
                SELECT email, current_url AS mailbox_url, status,
                       first_uploaded_at, last_uploaded_at, upload_count
                FROM mailboxes {where}
                ORDER BY last_uploaded_at DESC, id DESC
                LIMIT ? OFFSET ?
                """,
                [*params, page_size, (page - 1) * page_size],
            ).fetchall()
        return jsonify(
            ok=True,
            items=[dict(row) for row in rows],
            total=total,
            page=page,
            page_size=page_size,
        )

    @app.get(f"{API_PREFIX}/uploads")
    @manager_required
    def api_uploads():
        page = _safe_int(request.args.get("page"), 1, 1, 1_000_000)
        page_size = _safe_int(request.args.get("page_size"), 50, 1, 100)
        search = str(request.args.get("search") or "").strip().lower()[:200]
        action = str(request.args.get("action") or "").strip().lower()
        clauses = []
        params: list[Any] = []
        if search:
            clauses.append("e.email_key LIKE ? ESCAPE '\\'")
            params.append(f"%{_escape_like(search)}%")
        if action in {"created", "updated", "duplicate"}:
            clauses.append("e.action = ?")
            params.append(action)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with _database(app) as connection:
            total = int(connection.execute(
                f"SELECT COUNT(*) FROM upload_events e {where}",
                params,
            ).fetchone()[0])
            rows = connection.execute(
                f"""
                SELECT e.id, e.batch_id, e.email, e.action, e.previous_url,
                       e.submitted_url, e.uploaded_at, b.source,
                       b.submitted AS batch_submitted, b.created AS batch_created,
                       b.updated AS batch_updated, b.duplicates AS batch_duplicates,
                       b.rejected AS batch_rejected
                FROM upload_events e
                JOIN upload_batches b ON b.batch_id = e.batch_id
                {where}
                ORDER BY e.uploaded_at DESC, e.id DESC
                LIMIT ? OFFSET ?
                """,
                [*params, page_size, (page - 1) * page_size],
            ).fetchall()
        return jsonify(
            ok=True,
            items=[dict(row) for row in rows],
            total=total,
            page=page,
            page_size=page_size,
        )

    return app


__all__ = ["API_PREFIX", "MANAGER_PREFIX", "create_app", "import_batch", "init_database"]
