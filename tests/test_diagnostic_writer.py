from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from mac_overrides.diagnostic_store import DiagnosticStore
from mac_overrides.diagnostic_writer import DiagnosticEventWriter, LogContext
from mac_overrides.free_log_runtime import FreeLogStore


class DiagnosticEventWriterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(prefix="gptphone-writer-")
        self.root = Path(self.temp_dir.name)
        self.store = DiagnosticStore(self.root / "diagnostics")

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_context_and_sequence_are_stable_and_subject_is_hashed(self) -> None:
        writer = DiagnosticEventWriter(
            self.store,
            context=LogContext(
                chain="free", workflow="register", driver="camoufox",
                batch_id="batch-1", task_id="free-task-1",
            ),
        )
        first = writer.add(
            "开始处理 email=private@example.com token=secret-value",
            "info",
            node_code="free_camoufox_signup",
            email="private@example.com",
        )
        second = writer.add(
            "OTP 失败 code=123456",
            "error",
            node_code="free_email_otp_wait",
            failure={
                "error_code": "otp_timeout",
                "retryable": True,
                "raw_body": "must-not-persist",
            },
        )

        self.assertTrue(first.startswith("LOG-"))
        self.assertEqual(second, first)
        detail = self.store.incident(first)
        assert detail is not None
        self.assertEqual(len(detail["events"]), 2)
        self.assertEqual([event["sequence"] for event in detail["events"]], [1, 2])
        self.assertEqual(detail["driver"], "camoufox")
        rendered = str(detail)
        for secret in ("private@example.com", "secret-value", "123456", "must-not-persist"):
            self.assertNotIn(secret, rendered)
        self.assertEqual(detail["subject_display"], "p***@example.com")
        self.assertRegex(detail["subject_ref"], r"^[0-9a-f]{32}$")

    def test_best_effort_storage_failure_returns_empty_without_leaking_payload(self) -> None:
        class BrokenStore:
            def __init__(self) -> None:
                self.noted: list[tuple[str, str]] = []

            def record(self, _fields):
                raise OSError("disk full token=private")

            def note_write_failure(self, operation, error):
                self.noted.append((operation, type(error).__name__))

        broken = BrokenStore()
        writer = DiagnosticEventWriter(broken)
        self.assertEqual(
            writer.record({"message": "token=private", "task_id": "free-x"}),
            "",
        )
        self.assertEqual(broken.noted, [("writer_record", "OSError")])

    def test_structured_prefix_cannot_bypass_subject_redaction(self) -> None:
        captured: list[dict[str, object]] = []

        class CaptureStore:
            def record(self, fields):
                captured.append(dict(fields))
                return "LOG-20260830-ABCDEFGH"

        writer = DiagnosticEventWriter(CaptureStore())
        writer.add(
            "[private@example.com/free_email_otp_wait] email=private@example.com",
            "error",
            task_id="free-prefix",
        )
        self.assertEqual(len(captured), 1)
        rendered = str(captured[0])
        self.assertNotIn("private@example.com", rendered)
        self.assertIn("<邮箱>", rendered)

    def test_writer_masks_supplied_subject_display_before_injected_store(self) -> None:
        captured: list[dict[str, object]] = []

        class CaptureStore:
            def record(self, fields):
                captured.append(dict(fields))
                return "LOG-20260830-ABCDEFGH"

        writer = DiagnosticEventWriter(CaptureStore())
        writer.record(
            {
                "task_id": "free-display",
                "outcome": "error",
                "subject_kind": "email",
                "subject_display": "private@example.com",
            }
        )
        self.assertEqual(captured[0]["subject_display"], "p***@example.com")
        self.assertNotIn("private@example.com", str(captured[0]))

    def test_free_log_facade_uses_sqlite_as_source_when_projection_disabled(self) -> None:
        data_dir = self.root / "free_register"
        logs = FreeLogStore(
            data_dir,
            diagnostic_store=self.store,
            legacy_projection=False,
        )
        logs.add(
            "[free-source/free_access_token] token=private",
            "info",
            task_id="free-source",
            node_code="free_access_token",
        )
        self.assertFalse((data_dir / "logs.json").exists())
        self.assertFalse((data_dir / "task_logs").exists())
        rows = logs.snapshot("free-source")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["task_id"], "free-source")
        self.assertEqual(rows[0]["node_code"], "free_access_token")
        self.assertNotIn("private", str(rows))

    def test_free_log_snapshot_isolated_by_workflow_and_driver(self) -> None:
        data_dir = self.root / "free_register"
        register = FreeLogStore(
            data_dir,
            diagnostic_store=self.store,
            legacy_projection=False,
            workflow="register",
            driver="protocol",
        )
        rebind = FreeLogStore(
            data_dir,
            diagnostic_store=self.store,
            legacy_projection=False,
            workflow="rebind",
            driver="protocol",
        )
        register.add(
            "注册阶段",
            "error",
            task_id="free-same-task",
            workflow="register",
            driver="protocol",
            node_code="free_entry",
        )
        rebind.add(
            "换绑阶段",
            "error",
            task_id="free-same-task",
            workflow="rebind",
            driver="protocol",
            node_code="free_rebind_otp",
        )
        register_rows = register.snapshot("free-same-task")
        rebind_rows = rebind.snapshot("free-same-task")
        self.assertEqual({row["node_code"] for row in register_rows}, {"free_entry"})
        self.assertEqual({row["node_code"] for row in rebind_rows}, {"free_rebind_otp"})

    def test_free_log_facade_forwards_nonlegacy_subject_reference_to_writer(self) -> None:
        """The facade must not drop a caller's safe writer subject contract."""
        data_dir = self.root / "free_register"
        logs = FreeLogStore(
            data_dir,
            diagnostic_store=self.store,
            legacy_projection=False,
        )

        logs.add(
            "账号阶段开始",
            "info",
            task_id="free-subject-ref",
            node_code="free_entry",
            subject_kind="email",
            subject_ref="subject-ref@example.com",
        )

        incidents = self.store.search({"task_id": "free-subject-ref"})
        self.assertEqual(len(incidents), 1)
        detail = self.store.incident(incidents[0]["incident_id"])
        assert detail is not None
        self.assertEqual(detail["subject_display"], "s***@example.com")
        self.assertRegex(detail["subject_ref"], r"^[0-9a-f]{32}$")
        self.assertNotIn("subject-ref@example.com", str(detail))

    def test_facade_can_run_one_shot_legacy_cleanup_without_touching_sqlite_events(self) -> None:
        data_dir = self.root / "free_register"
        data_dir.mkdir()
        (data_dir / "logs.json").write_text("[]", encoding="utf-8")
        logs = FreeLogStore(
            data_dir,
            diagnostic_store=self.store,
            legacy_projection=False,
            cleanup_legacy=True,
        )
        self.assertTrue(logs.legacy_cleanup_result.marker_written)
        self.assertFalse((data_dir / "logs.json").exists())
        self.assertTrue(self.store.health()["ok"])

    def test_structured_facade_can_surface_diagnostic_read_errors_to_routes(self) -> None:
        class BrokenStore:
            def search(self, _query):
                raise OSError("diagnostic storage unavailable")

        logs = FreeLogStore(
            self.root / "free_register",
            diagnostic_store=BrokenStore(),
            legacy_projection=False,
            strict_diagnostic_reads=True,
        )
        with self.assertRaises(OSError):
            logs.snapshot("free-read")

    def test_legacy_clear_does_not_follow_symlinked_task_log_directory(self) -> None:
        data_dir = self.root / "free_register"
        data_dir.mkdir()
        outside = self.root / "outside-task-logs"
        outside.mkdir()
        protected = outside / "protected.json"
        protected.write_text("[]", encoding="utf-8")
        (data_dir / "task_logs").symlink_to(outside, target_is_directory=True)

        logs = FreeLogStore(data_dir, legacy_projection=True)
        logs.clear()

        self.assertTrue(protected.exists())
        self.assertTrue((data_dir / "task_logs").is_symlink())

    def test_facade_cleanup_rejects_symlinked_free_root(self) -> None:
        target = self.root / "external-free-register"
        target.mkdir()
        protected = target / "logs.json"
        protected.write_text("[]", encoding="utf-8")
        lexical_root = self.root / "free_register"
        lexical_root.symlink_to(target, target_is_directory=True)

        logs = FreeLogStore(
            lexical_root,
            diagnostic_store=self.store,
            legacy_projection=False,
            cleanup_legacy=True,
        )

        self.assertTrue(logs.legacy_cleanup_result["failed"])
        self.assertEqual(logs.legacy_cleanup_result["error_type"], "ValueError")
        self.assertTrue(protected.exists())


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
