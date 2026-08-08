from __future__ import annotations

from types import SimpleNamespace
import threading
import unittest

from mac_overrides.importer_watch_runtime import finalize_importer_watch


class _NotificationService:
    def __init__(self, *, observe_error: Exception | None = None) -> None:
        self.observe_error = observe_error
        self.finalizations: list[dict[str, object]] = []

    def observe_run(self, _run_id, _aggregate, *, sms_exhausted):
        if self.observe_error is not None:
            raise self.observe_error

    def finalize_run(self, _run_id, _aggregate, **kwargs):
        self.finalizations.append(dict(kwargs))


class ImporterWatchRuntimeTests(unittest.TestCase):
    @staticmethod
    def _context(service: _NotificationService) -> dict[str, object]:
        return {
            "run_id": "run-safe-id",
            "batch_id": "batch-safe-id",
            "finished_at": 0,
            "last_activity_at": 0,
            "stop_event": threading.Event(),
            "service": service,
        }

    def test_notification_failure_does_not_prevent_batch_reconciliation(self):
        service = _NotificationService(observe_error=RuntimeError("private response"))
        logs: list[tuple[str, str]] = []
        importer = SimpleNamespace(
            unresolved=True,
            futures=(),
            _log=lambda message, level: logs.append((message, level)),
        )

        def unfinished(current):
            return ("T001-safe",) if current.unresolved else ()

        def reconcile(current, _context):
            current.unresolved = False

        finalize_importer_watch(
            importer,
            self._context(service),
            watch_failed=False,
            aggregate_fn=lambda *_args, **_kwargs: (object(), 123),
            unfinished_fn=unfinished,
            reconcile_fn=reconcile,
            sms_exhausted_fn=lambda: False,
            now_fn=lambda: 456,
        )

        self.assertFalse(importer.unresolved)
        self.assertEqual(
            [item["completed"] for item in service.finalizations],
            [False, True],
        )
        joined = "\n".join(message for message, _level in logs)
        self.assertIn("[运行结束通知/run_notification_observe]", joined)
        self.assertNotIn("private response", joined)

    def test_reconciliation_failure_is_logged_and_never_reports_complete(self):
        service = _NotificationService()
        logs: list[tuple[str, str]] = []
        importer = SimpleNamespace(
            futures=(),
            _log=lambda message, level: logs.append((message, level)),
        )

        def fail_reconcile(_importer, _context):
            raise OSError("/private/credential-row")

        finalize_importer_watch(
            importer,
            self._context(service),
            watch_failed=False,
            aggregate_fn=lambda *_args, **_kwargs: (object(), 123),
            unfinished_fn=lambda _importer: (),
            reconcile_fn=fail_reconcile,
            sms_exhausted_fn=lambda: False,
        )

        self.assertEqual(len(service.finalizations), 1)
        self.assertFalse(service.finalizations[0]["completed"])
        self.assertEqual(
            service.finalizations[0]["termination_reason"],
            "batch_reconcile_failed",
        )
        joined = "\n".join(message for message, _level in logs)
        self.assertIn("[运行批次对账/run_batch_manifest]", joined)
        self.assertNotIn("credential-row", joined)


if __name__ == "__main__":
    unittest.main()
