"""SQLite-backed adapter for the historical Free proxy pool API."""

from __future__ import annotations

import copy
import json
import sqlite3
import time
from pathlib import Path
from typing import Any, Iterable, Mapping
from urllib.parse import unquote, urlsplit

try:
    from .free_proxy_store import FreeProxyPool as _LegacyProxyPool
    from .free_register_common import fingerprint
    from .free_storage import FreeSQLiteStore, _partition_json
except ImportError:  # pragma: no cover - recovery imports
    from free_proxy_store import FreeProxyPool as _LegacyProxyPool  # type: ignore[no-redef]
    from free_register_common import fingerprint  # type: ignore[no-redef]
    from free_storage import FreeSQLiteStore, _partition_json  # type: ignore[no-redef]


class SQLiteFreeProxyPool(_LegacyProxyPool):
    """SQLite-backed proxy pool preserving the mature policy implementation.

    The parent class contains the transport/probe/quarantine policy and only
    calls ``_load``/``_save`` for persistence.  Redirecting those two methods
    keeps behavior aligned with the reference implementation without creating
    a second proxy state machine.
    """

    def __init__(self, data_dir: str | Path, *, storage: FreeSQLiteStore | None = None, **kwargs: Any) -> None:
        super().__init__(data_dir, **kwargs)
        self.storage = storage or FreeSQLiteStore(self.data_dir)
        self.path = self.storage.path

    def replace_text(self, content: str, **kwargs: Any) -> int:
        """Replace the whole pool atomically.

        The inherited ``_save`` upserts rows, so honouring the parent's
        replace contract requires clearing the table before writing the new
        snapshot; otherwise every settings-page save would accumulate stale
        proxies forever.
        """
        try:
            from .free_proxy_store import SINGLE_POOL_COUNTRY, SINGLE_POOL_GROUP
        except ImportError:  # pragma: no cover - recovery imports
            from free_proxy_store import SINGLE_POOL_COUNTRY, SINGLE_POOL_GROUP  # type: ignore[no-redef]
        try:
            from .free_register_common import FreeRegisterError
        except ImportError:  # pragma: no cover - recovery imports
            from free_register_common import FreeRegisterError  # type: ignore[no-redef]
        incoming = self._parse_lines(
            content,
            country=SINGLE_POOL_COUNTRY,
            group=SINGLE_POOL_GROUP,
            scheme=str(kwargs.get("scheme") or self.default_scheme),
            source_label=str(kwargs.get("source_label") or kwargs.get("provider") or ""),
        )
        if str(content or "").strip() and not incoming:
            raise FreeRegisterError("free_proxy_pool", "Free 代理池", "Free 代理池没有有效代理")
        with self.storage._transaction():  # noqa: SLF001 - adapter boundary
            with self.storage._connection() as db:  # noqa: SLF001 - adapter boundary
                db.execute("BEGIN IMMEDIATE")
                try:
                    db.execute("DELETE FROM proxies")
                    db.execute("DELETE FROM resource_leases WHERE resource_type='proxy'")
                    db.execute("COMMIT")
                except BaseException:
                    try:
                        db.execute("ROLLBACK")
                    except sqlite3.OperationalError:
                        pass
                    raise
        self._save(incoming)
        return len(incoming)


    def _load(self) -> list[dict[str, Any]]:
        output: list[dict[str, Any]] = []
        now_epoch = time.time()
        with self.storage._connection() as db:  # noqa: SLF001 - adapter boundary
            rows = db.execute("SELECT * FROM proxies ORDER BY updated_at DESC,proxy_id ASC").fetchall()
            # One grouped lease read replaces the per-proxy subquery; the PK
            # (resource_type, resource_id, owner) keeps the same owner ordering
            # the per-row query produced.
            leases_by_proxy: dict[str, list[sqlite3.Row]] = {}
            for lease in db.execute(
                "SELECT resource_id,owner,lease_until FROM resource_leases "
                "WHERE resource_type='proxy' AND lease_until>? ORDER BY resource_id,owner",
                (now_epoch,),
            ).fetchall():
                leases_by_proxy.setdefault(str(lease["resource_id"]), []).append(lease)
            for row in rows:
                try:
                    payload = self.storage._row_payload(row)  # noqa: SLF001 - adapter boundary
                except (TypeError, ValueError, json.JSONDecodeError):
                    # A single damaged payload must not hide the rest of the
                    # shared proxy pool; retain scalar identity/health fields
                    # and let the next successful probe repair metadata.
                    payload = {}
                proxy = str(row["proxy"] or "")
                parsed = urlsplit(proxy)
                lease_metadata = {
                    str(item.get("owner") or ""): item
                    for item in (payload.get("leases") or [])
                    if isinstance(item, Mapping) and str(item.get("owner") or "").strip()
                }
                proxy_id = str(row["proxy_id"])
                leases = [
                    {
                        "owner": str(item["owner"]),
                        "until": float(item["lease_until"]),
                        "batch_id": str(
                            lease_metadata.get(str(item["owner"]), {}).get("batch_id")
                            or payload.get("lease_batch_id")
                            or ""
                        ),
                        "task_id": str(
                            lease_metadata.get(str(item["owner"]), {}).get("task_id")
                            or payload.get("lease_task_id")
                            or ""
                        ),
                    }
                    for item in leases_by_proxy.get(proxy_id, [])
                ]
                status = str(row["status"] or "unknown")
                if status == "healthy":
                    status = "available"
                if status not in {"unknown", "available", "quarantined"}:
                    status = "unknown"
                record = {
                    **payload,
                    "proxy_id": str(row["proxy_id"]),
                    "proxy": proxy,
                    "host": str(parsed.hostname or payload.get("host") or ""),
                    "port": int(parsed.port or payload.get("port") or 0),
                    "username": unquote(str(parsed.username or payload.get("username") or "")),
                    "password": unquote(str(parsed.password or payload.get("password") or "")),
                    "scheme": str(row["scheme"] or parsed.scheme or self.default_scheme).lower(),
                    "effective_scheme": str(payload.get("effective_scheme") or row["scheme"] or parsed.scheme or self.default_scheme).lower(),
                    "country": "",
                    "group": "",
                    "enabled": bool(row["enabled"]),
                    "status": status,
                    "leases": leases,
                    "lease_owner": str(row["lease_owner"] or ""),
                    "lease_until": row["lease_until"],
                    # Keep a private snapshot of the owners observed in this
                    # read.  ``_save`` uses it to distinguish an intentional
                    # release from a lease acquired concurrently by another
                    # process; the marker is never persisted in payloads.
                    "_lease_snapshot_owners": tuple(
                        sorted(
                            str(item.get("owner") or "").strip()
                            for item in leases
                            if str(item.get("owner") or "").strip()
                        )
                    ),
                    "_lease_snapshot_until": {
                        str(item.get("owner") or "").strip(): float(item.get("until") or 0)
                        for item in leases
                        if str(item.get("owner") or "").strip()
                    },
                    "_normalized": proxy,
                }
                record["_storage_revision"] = int(row["revision"] or 0)
                identity = f"{record['host']}\x00{record['port']}\x00{record['username']}\x00{record['password']}"
                record["_identity"] = identity
                output.append(record)
        return output

    def _save(self, rows: Iterable[Mapping[str, Any]]) -> None:
        values = [dict(row) for row in rows if isinstance(row, Mapping)]
        now = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())
        now_epoch = time.time()
        with self.storage._transaction():  # noqa: SLF001 - adapter boundary
            with self.storage._connection() as db:  # noqa: SLF001
                db.execute("BEGIN IMMEDIATE")
                try:
                    for row in values:
                        proxy = str(row.get("_normalized") or row.get("proxy") or "").strip()
                        if not proxy:
                            continue
                        parsed = urlsplit(proxy)
                        proxy_id = str(row.get("proxy_id") or fingerprint(proxy))
                        current_row = db.execute(
                            "SELECT * FROM proxies WHERE proxy_id=?", (proxy_id,)
                        ).fetchone()
                        current_payload: dict[str, Any] = {}
                        if current_row is not None:
                            try:
                                decoded = json.loads(str(current_row["payload"] or "{}"))
                            except (TypeError, ValueError, json.JSONDecodeError):
                                decoded = {}
                            if isinstance(decoded, Mapping):
                                current_payload = copy.deepcopy(dict(decoded))

                        # A legacy caller hands this adapter a complete
                        # in-memory snapshot.  Only owners present in that
                        # snapshot may be removed: an owner acquired after the
                        # snapshot was read is unknown and must survive this
                        # write.  This makes stale health/config writes safe
                        # across processes while preserving explicit release
                        # (the releasing call loads a fresh owner snapshot).
                        raw_snapshot_owners = row.get("_lease_snapshot_owners")
                        if isinstance(raw_snapshot_owners, (list, tuple, set, frozenset)):
                            snapshot_owners = {
                                str(owner or "").strip()
                                for owner in raw_snapshot_owners
                                if str(owner or "").strip()
                            }
                        else:
                            snapshot_owners = set()
                        raw_snapshot_until = row.get("_lease_snapshot_until")
                        snapshot_until: dict[str, float] = {}
                        if isinstance(raw_snapshot_until, Mapping):
                            for owner, value in raw_snapshot_until.items():
                                owner_text = str(owner or "").strip()
                                try:
                                    until = float(value or 0)
                                except (TypeError, ValueError):
                                    until = 0.0
                                if owner_text and until > 0:
                                    snapshot_until[owner_text] = until
                        raw_snapshot_revision = row.get("_storage_revision")
                        try:
                            snapshot_revision = int(raw_snapshot_revision)
                        except (TypeError, ValueError):
                            snapshot_revision = None
                        current_revision = (
                            int(current_row["revision"] or 0)
                            if current_row is not None
                            else None
                        )
                        revision_changed = (
                            snapshot_revision is not None
                            and current_revision is not None
                            and current_revision != snapshot_revision
                        )
                        current_lease_metadata: dict[str, dict[str, Any]] = {}
                        raw_current_leases = current_payload.get("leases")
                        if isinstance(raw_current_leases, list):
                            for item in raw_current_leases:
                                if not isinstance(item, Mapping):
                                    continue
                                owner = str(item.get("owner") or "").strip()
                                if owner:
                                    current_lease_metadata[owner] = dict(item)

                        existing_leases = db.execute(
                            "SELECT owner,lease_until FROM resource_leases "
                            "WHERE resource_type='proxy' AND resource_id=?",
                            (proxy_id,),
                        ).fetchall()
                        existing_owners = {
                            str(item["owner"] or "").strip()
                            for item in existing_leases
                            if str(item["owner"] or "").strip()
                        }

                        desired = row.get("leases") if isinstance(row.get("leases"), list) else []
                        desired_by_owner: dict[str, dict[str, Any]] = {}
                        for item in desired:
                            if not isinstance(item, Mapping):
                                continue
                            owner = str(item.get("owner") or "").strip()
                            try:
                                until = float(item.get("until") or 0)
                            except (TypeError, ValueError):
                                until = 0
                            # If this owner existed in the loaded snapshot but
                            # disappeared while another writer advanced the
                            # row, it was explicitly released (or expired) in
                            # the meantime.  Do not recreate it from the stale
                            # health/config snapshot.  Fresh lease/heartbeat
                            # calls have an unchanged revision and therefore
                            # continue to renew their owner normally.
                            if (
                                owner
                                and until > now_epoch
                                and not (
                                    revision_changed
                                    and owner in snapshot_owners
                                    and owner not in existing_owners
                                )
                            ):
                                desired_by_owner[owner] = {
                                    "owner": owner,
                                    "until": until,
                                    "batch_id": str(item.get("batch_id") or ""),
                                    "task_id": str(item.get("task_id") or ""),
                                }

                        # Remove expired rows and owners explicitly removed
                        # from the snapshot.  Concurrently added owners are
                        # absent from ``snapshot_owners`` and are retained.
                        remove_owners = {
                            owner
                            for owner in existing_owners
                            if owner not in desired_by_owner
                            and (
                                (
                                    owner in snapshot_owners
                                    and next(
                                        (
                                            float(item["lease_until"] or 0)
                                            for item in existing_leases
                                            if str(item["owner"] or "").strip() == owner
                                        ),
                                        0.0,
                                    ) <= snapshot_until.get(owner, 0.0)
                                )
                                or next(
                                    (
                                        float(item["lease_until"] or 0)
                                        for item in existing_leases
                                        if str(item["owner"] or "").strip() == owner
                                    ),
                                    0,
                                ) <= now_epoch
                            )
                        }
                        for owner in remove_owners:
                            db.execute(
                                "DELETE FROM resource_leases WHERE resource_type='proxy' "
                                "AND resource_id=? AND owner=?",
                                (proxy_id, owner),
                            )

                        # Refresh desired owners and add new owners.  Existing
                        # unknown owners are intentionally left untouched.
                        for owner, item in desired_by_owner.items():
                            db.execute(
                                "INSERT INTO resource_leases(resource_type,resource_id,owner,lease_until,created_at,updated_at) "
                                "VALUES('proxy',?,?,?,?,?) "
                                "ON CONFLICT(resource_type,resource_id,owner) DO UPDATE SET "
                                # Never shorten a lease renewed by another
                                # worker after this snapshot was read.
                                "lease_until=MAX(resource_leases.lease_until,excluded.lease_until),updated_at=excluded.updated_at",
                                (proxy_id, owner, item["until"], now, now),
                            )

                        final_lease_rows = db.execute(
                            "SELECT owner,lease_until FROM resource_leases "
                            "WHERE resource_type='proxy' AND resource_id=? AND lease_until>? "
                            "ORDER BY owner ASC",
                            (proxy_id, now_epoch),
                        ).fetchall()
                        final_leases: list[dict[str, Any]] = []
                        for item in final_lease_rows:
                            owner = str(item["owner"] or "").strip()
                            if not owner:
                                continue
                            metadata = desired_by_owner.get(owner) or current_lease_metadata.get(owner) or {}
                            final_leases.append(
                                {
                                    "owner": owner,
                                    "until": float(item["lease_until"]),
                                    "batch_id": str(metadata.get("batch_id") or ""),
                                    "task_id": str(metadata.get("task_id") or ""),
                                }
                            )
                        latest = max(final_leases, key=lambda item: float(item["until"]), default=None)
                        payload = {
                            str(key): copy.deepcopy(value)
                            for key, value in row.items()
                            if str(key) not in {
                                "_identity",
                                "_normalized",
                                "_storage_revision",
                                "_lease_snapshot_owners",
                                "_lease_snapshot_until",
                                "proxy",
                                "proxy_id",
                                "scheme",
                                "status",
                                "enabled",
                                "lease_owner",
                                "lease_until",
                            }
                        }
                        payload["proxy"] = proxy
                        payload["proxy_id"] = proxy_id
                        payload["leases"] = final_leases
                        payload["lease_owner"] = str(latest["owner"]) if latest else ""
                        payload["lease_until"] = float(latest["until"]) if latest else None
                        payload["lease_batch_id"] = str(latest.get("batch_id") or "") if latest else ""
                        payload["lease_task_id"] = str(latest.get("task_id") or "") if latest else ""
                        scheme = str(row.get("scheme") or parsed.scheme or self.default_scheme).lower()
                        status = str(row.get("status") or "unknown")
                        if status == "healthy":
                            status = "available"
                        public_payload, private_payload = _partition_json(payload)
                        db.execute(
                            "INSERT INTO proxies(proxy_id,proxy,scheme,status,enabled,lease_owner,lease_until,revision,created_at,updated_at,payload,private_payload) "
                            "VALUES(?,?,?,?,?,?,?,0,?,?,?,?) "
                            "ON CONFLICT(proxy_id) DO UPDATE SET proxy=excluded.proxy,scheme=excluded.scheme,status=excluded.status,"
                            "enabled=excluded.enabled,lease_owner=excluded.lease_owner,lease_until=excluded.lease_until,"
                            "revision=proxies.revision+1,updated_at=excluded.updated_at,payload=excluded.payload,private_payload=excluded.private_payload",
                            (
                                proxy_id,
                                proxy,
                                scheme,
                                status,
                                int(bool(row.get("enabled", True))),
                                str(latest["owner"]) if latest else "",
                                float(latest["until"]) if latest else None,
                                now,
                                now,
                                json.dumps(public_payload, ensure_ascii=False, sort_keys=True),
                                json.dumps(private_payload, ensure_ascii=False, sort_keys=True),
                            ),
                        )
                    db.execute("COMMIT")
                except BaseException:
                    try:
                        db.execute("ROLLBACK")
                    except sqlite3.OperationalError:
                        pass
                    raise

    def public(self) -> dict[str, Any]:
        """Return the legacy proxy projection plus a stable ``proxies`` alias.

        Older UI callers use ``rows`` while the SQLite adapter contract uses
        ``proxies``.  Both keys point to independently copied rows so callers
        cannot mutate the adapter's in-memory projection through either view.
        """

        projection = dict(super().public())
        rows = projection.get("rows")
        if not isinstance(rows, list):
            rows = []
        normalized_rows: list[Any] = []
        for item in rows:
            if not isinstance(item, Mapping):
                normalized_rows.append(item)
                continue
            row = dict(item)
            # ``proxy`` is the historical public field name; its value is
            # always the credential-free masked representation.
            row.setdefault("proxy", row.get("masked", ""))
            normalized_rows.append(row)
        projection["rows"] = normalized_rows
        projection["proxies"] = [dict(item) if isinstance(item, Mapping) else item for item in projection["rows"]]
        return projection

    def release_owner(self, owner: str) -> int:
        """Release all proxy leases held by an interrupted task owner."""
        releaser = getattr(self.storage, "release_proxy_leases", None)
        if not callable(releaser):
            return 0
        result = releaser(str(owner or "").strip())
        try:
            return int(result or 0)
        except (TypeError, ValueError):
            return 0

    # Keep the operation discoverable under the storage-oriented name too.
    release_leases_for_owner = release_owner


__all__ = ["SQLiteFreeProxyPool"]
