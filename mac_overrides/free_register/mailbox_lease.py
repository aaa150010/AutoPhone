"""Two-phase mailbox lease coordination for Free registration workers.

The coordinator deliberately knows nothing about OTP retrieval.  It only
protects a mailbox while a transport is being prepared and records the
irreversible hand-off immediately before the driver submits the address.
"""

from __future__ import annotations

import threading
from typing import Any, Mapping

try:
    from ..free_storage import FreeSQLiteStore
except ImportError:  # pragma: no cover
    from free_storage import FreeSQLiteStore  # type: ignore[no-redef]

from .contracts import MailboxLease


class MailboxLeaseConflict(RuntimeError):
    """Raised when a lease cannot be confirmed for its original owner."""


class MailboxLeaseCoordinator:
    """Small thread-safe facade over :class:`FreeSQLiteStore` mailbox leases."""

    def __init__(self, storage: FreeSQLiteStore, *, lease_seconds: int = 180) -> None:
        self.storage = storage
        self.lease_seconds = max(5, int(lease_seconds))
        self._lock = threading.RLock()
        self._leases: dict[str, MailboxLease] = {}

    @staticmethod
    def _lease_from_row(row: Mapping[str, Any], owner: str, *, fallback_confirmed: bool = False) -> MailboxLease:
        payload = row.get("payload")
        payload = payload if isinstance(payload, Mapping) else {}
        try:
            lease_until = float(row.get("lease_until") or 0)
        except (TypeError, ValueError, OverflowError):
            lease_until = 0.0
        try:
            revision = max(0, int(row.get("revision") or 0))
        except (TypeError, ValueError, OverflowError):
            revision = 0
        confirmed_value = payload.get("lease_confirmed", fallback_confirmed)
        if isinstance(confirmed_value, bool):
            confirmed = confirmed_value
        elif isinstance(confirmed_value, (int, float)) and not isinstance(confirmed_value, bool):
            confirmed = confirmed_value in {1, 1.0}
        elif isinstance(confirmed_value, str):
            confirmed = confirmed_value.strip().lower() in {"1", "true", "yes", "on", "enabled"}
        else:
            confirmed = bool(fallback_confirmed)
        return MailboxLease(
            row_id=str(row.get("row_id") or ""),
            owner=str(owner or row.get("lease_owner") or ""),
            lease_until=lease_until,
            revision=revision,
            confirmed=confirmed,
            confirmed_at=payload.get("lease_confirmed_at"),
        )

    def acquire(
        self,
        row_id: str,
        *,
        task_id: str,
        batch_id: str = "",
        driver: str = "protocol",
        lease_seconds: int | None = None,
    ) -> MailboxLease | None:
        """Claim an available row without consuming it.

        ``task_id`` is used as the lease owner, which makes recovery possible
        after a process restart without persisting a second private mapping.
        """
        normalized_row = str(row_id or "").strip()
        owner = str(task_id or "").strip()
        if not normalized_row or not owner:
            return None
        with self._lock:
            existing = self._leases.get(owner)
            if existing is not None and existing.row_id == normalized_row and not existing.expired:
                # A second process may have released or reassigned the row
                # since the last call.  Refresh the durable row before
                # treating the in-memory lease as authoritative.
                refreshed = self._resolve(task_id=owner, row_id=normalized_row)
                if refreshed is not None:
                    return refreshed
            row = self.storage.claim_mailbox(
                owner=owner,
                row_id=normalized_row,
                lease_seconds=lease_seconds or self.lease_seconds,
                claimed_status="reserved",
            )
            if row is None:
                # The legacy manager reserves a row for the batch before it
                # creates the task.  Adopt that reservation atomically rather
                # than requiring a second status transition through
                # ``available`` (which would open a dispatch race).
                current = self.storage.get_mailbox(normalized_row)
                if (
                    current is not None
                    and str(current.get("status") or "") == "reserved"
                    and str(current.get("batch_id") or "") == str(batch_id or "")
                    and self.storage.lease_mailbox(
                        normalized_row,
                        owner=owner,
                        lease_seconds=lease_seconds or self.lease_seconds,
                        expected_revision=int(current.get("revision") or 0),
                    )
                ):
                    row = self.storage.get_mailbox(normalized_row)
            if row is None:
                return None
            lease = self._lease_from_row(row, owner)
            self._leases[owner] = lease
            return lease

    def _resolve(self, *, task_id: str, row_id: str = "") -> MailboxLease | None:
        owner = str(task_id or "").strip()
        normalized_row = str(row_id or "").strip()
        with self._lock:
            if not owner:
                return None
            cached = self._leases.get(owner)
            if normalized_row and cached is not None and cached.row_id != normalized_row:
                # A task cannot address a different row through a stale
                # cached owner mapping.  Drop the cache and require a fresh
                # acquire instead of guessing which lease was intended.
                self._leases.pop(owner, None)
                return None
            candidate_row = normalized_row or (cached.row_id if cached is not None else "")
            if not candidate_row:
                return None
            try:
                row = self.storage.get_mailbox(candidate_row)
            except Exception:
                self._leases.pop(owner, None)
                return None
            if (
                not row
                or str(row.get("row_id") or "") != candidate_row
                or str(row.get("lease_owner") or "") != owner
            ):
                self._leases.pop(owner, None)
                return None
            durable = self._lease_from_row(row, owner)
            if durable.expired:
                self._leases.pop(owner, None)
                return None
            if cached is not None and cached.row_id != durable.row_id:
                self._leases.pop(owner, None)
                return None
            # Revision, expiry and confirmation may legitimately change in a
            # different process (for example a heartbeat renewal).  The
            # durable row is authoritative, so refresh all of them before a
            # compare-and-set operation.
            self._leases[owner] = durable
            return durable

    def confirm(
        self,
        *,
        task_id: str,
        row_id: str = "",
        batch_id: str = "",
        driver: str = "protocol",
    ) -> bool:
        """Mark the lease consumed at the exact email-submit boundary."""
        with self._lock:
            lease = self._resolve(task_id=task_id, row_id=row_id)
            if lease is None:
                return False
            row = self.storage.confirm_mailbox_lease(
                lease.row_id,
                owner=lease.owner,
                task_id=str(task_id or lease.owner),
                batch_id=batch_id,
                driver=driver,
                expected_revision=lease.revision,
            )
            if row is None:
                # A same-task retry may have confirmed the row in another
                # thread. Re-read and accept only that exact task identity.
                current = self.storage.get_mailbox(lease.row_id)
                payload = current.get("payload") if isinstance(current, Mapping) else {}
                if (
                    isinstance(current, Mapping)
                    and str(current.get("lease_owner") or "") == lease.owner
                    and isinstance(payload, Mapping)
                    and payload.get("lease_confirmed")
                    and str(payload.get("task_id") or "") == str(task_id)
                ):
                    self._leases[lease.owner] = self._lease_from_row(current, lease.owner, fallback_confirmed=True)
                    return True
                return False
            self._leases[lease.owner] = self._lease_from_row(row, lease.owner, fallback_confirmed=True)
            return True

    def renew(
        self,
        *,
        task_id: str,
        row_id: str = "",
        lease_seconds: int | None = None,
    ) -> bool:
        """Renew one live mailbox lease and refresh its CAS revision.

        Mailbox leases are acquired before a worker enters the transport so
        another task cannot claim the reserved row while it is queued.  A
        long queue or a slow browser startup can outlive the initial lease,
        therefore the manager heartbeat calls this method periodically.  The
        refreshed row is copied back into the coordinator cache; otherwise a
        later ``confirm`` would use the pre-renewal revision and fail its
        compare-and-set guard.
        """
        owner = str(task_id or "").strip()
        if not owner:
            return False
        seconds = max(5, int(lease_seconds or self.lease_seconds))
        with self._lock:
            lease = self._resolve(task_id=owner, row_id=row_id)
            if lease is None or lease.expired:
                return False
            renewed = self.storage.renew_lease(
                "mailbox",
                lease.row_id,
                owner=owner,
                lease_seconds=seconds,
                expected_revision=lease.revision,
            )
            if not renewed:
                # A lifecycle write in another process may have advanced the
                # revision without replacing this owner's lease. Re-read and
                # retry exactly once only when ownership is still unchanged;
                # never use this path to steal a row from another task.
                current = self.storage.get_mailbox(lease.row_id)
                if not current or str(current.get("lease_owner") or "") != owner:
                    self._leases.pop(owner, None)
                    return False
                current_lease = self._lease_from_row(current, owner)
                if current_lease.expired:
                    self._leases.pop(owner, None)
                    return False
                renewed = self.storage.renew_lease(
                    "mailbox",
                    current_lease.row_id,
                    owner=owner,
                    lease_seconds=seconds,
                    expected_revision=current_lease.revision,
                )
            if not renewed:
                return False
            current = self.storage.get_mailbox(lease.row_id)
            if not current or str(current.get("lease_owner") or "") != owner:
                self._leases.pop(owner, None)
                return False
            self._leases[owner] = self._lease_from_row(current, owner)
            return True

    def abort_confirmation(
        self,
        *,
        task_id: str,
        row_id: str = "",
        submission_definitely_not_started: bool = False,
    ) -> bool:
        """Undo only a confirmation whose submit primitive never started.

        The explicit proof flag keeps this method out of generic exception
        cleanup.  Ambiguous transport failures must use :meth:`release`, which
        preserves the confirmed row as ``pending_rerun``.
        """
        if submission_definitely_not_started is not True:
            return False
        owner = str(task_id or "").strip()
        if not owner:
            return False
        with self._lock:
            lease = self._resolve(task_id=owner, row_id=row_id)
            if lease is None or not lease.confirmed:
                return False
            current = self.storage.abort_mailbox_confirmation(
                lease.row_id,
                owner=lease.owner,
                task_id=owner,
                submission_definitely_not_started=True,
                expected_revision=lease.revision,
            )
            if current is None:
                # An external heartbeat may advance the row revision between
                # resolve and the CAS. Retry once only while the same live
                # owner/task confirmation is still durable.
                refreshed = self._resolve(task_id=owner, row_id=lease.row_id)
                if refreshed is None or not refreshed.confirmed:
                    return False
                current = self.storage.abort_mailbox_confirmation(
                    refreshed.row_id,
                    owner=refreshed.owner,
                    task_id=owner,
                    submission_definitely_not_started=True,
                    expected_revision=refreshed.revision,
                )
            if current is None:
                return False
            self._leases[owner] = self._lease_from_row(current, owner)
            return True

    def release(self, *, task_id: str, row_id: str = "", reusable: bool = True) -> bool:
        """Release an unconfirmed lease, or mark a confirmed row pending rerun."""
        with self._lock:
            lease = self._resolve(task_id=task_id, row_id=row_id)
            if lease is None:
                return False
            released = bool(
                self.storage.release_mailbox_lease(
                    lease.row_id, owner=lease.owner, reusable=bool(reusable)
                )
            )
            if released:
                self._leases.pop(lease.owner, None)
            return released

    def is_confirmed_durable(self, *, task_id: str, row_id: str = "") -> bool:
        """Read the task-bound confirmation without requiring a live lease.

        ``resource_leases`` is intentionally ephemeral and may be gone after
        expiry or process recovery.  The mailbox payload marker remains the
        source of truth for whether the address crossed the submit boundary.
        """
        owner = str(task_id or "").strip()
        normalized_row = str(row_id or "").strip()
        if not owner:
            return False
        if not normalized_row:
            with self._lock:
                cached = self._leases.get(owner)
                normalized_row = cached.row_id if cached is not None else ""
        if not normalized_row:
            return False
        return bool(
            self.storage.is_mailbox_confirmed_for_task(
                normalized_row,
                owner,
            )
        )

    def is_confirmed(self, *, task_id: str, row_id: str = "") -> bool:
        """Return confirmation from a live lease or its durable marker."""
        owner = str(task_id or "").strip()
        normalized_row = str(row_id or "").strip()
        if not owner:
            return False
        if not normalized_row:
            with self._lock:
                cached = self._leases.get(owner)
                normalized_row = cached.row_id if cached is not None else ""
        lease = self._resolve(task_id=owner, row_id=normalized_row)
        if lease is not None and lease.confirmed:
            return True
        # A lease may have expired (or its sidecar may have been removed) after
        # the email was submitted.  Never downgrade that durable fact to
        # "unconfirmed" merely because ownership is no longer live.
        return self.is_confirmed_durable(task_id=owner, row_id=normalized_row)

    def recover(self) -> dict[str, int]:
        """Recover expired and orphaned mailbox leases after startup."""
        with self._lock:
            recovered = self.storage.recover_expired_leases(resource_type="mailbox")
            # ``reserved`` can be persisted before a process dies between the
            # pool reservation and the normalized lease insert.  There is no
            # expired sidecar row for the generic recovery pass to find, so
            # run the narrow orphan scan as a second atomic operation.
            orphaned = self.storage.recover_orphaned_mailboxes()
            recovered["orphaned"] = int(orphaned)
            recovered["mailbox"] = int(recovered.get("mailbox", 0)) + int(orphaned)
            recovered["total"] = int(recovered.get("total", 0)) + int(orphaned)
            # Reconcile every cached owner against SQLite.  Filtering only by
            # the local expiry timestamp leaves a stale future lease usable
            # after another process has released or reassigned the row.
            refreshed: dict[str, MailboxLease] = {}
            for owner, cached in tuple(self._leases.items()):
                try:
                    row = self.storage.get_mailbox(cached.row_id)
                except Exception:
                    row = None
                if (
                    not row
                    or str(row.get("row_id") or "") != cached.row_id
                    or str(row.get("lease_owner") or "") != owner
                ):
                    continue
                lease = self._lease_from_row(row, owner)
                if not lease.expired:
                    refreshed[owner] = lease
            self._leases = refreshed
            return recovered


__all__ = ["MailboxLeaseConflict", "MailboxLeaseCoordinator"]
