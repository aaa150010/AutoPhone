from __future__ import annotations

from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from mac_overrides.diagnostic_store import DiagnosticStore


class DiagnosticStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(prefix="gptphone-diagnostics-")
        self.store = DiagnosticStore(Path(self.temp_dir.name))

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_task_events_share_an_incident_and_keep_first_failure(self) -> None:
        incident_id = self.store.record({
            "level": "info", "outcome": "started", "task_id": "T001-a",
            "chain": "free", "driver": "protocol", "node_code": "free_run_start",
            "message": "started",
        })
        self.assertTrue(incident_id)
        same = self.store.record({
            "level": "error", "outcome": "error", "task_id": "T001-a",
            "chain": "free", "driver": "protocol", "node_code": "free_email_otp_wait",
            "node_label": "等待 Free 邮箱验证码", "message": "token=private email=a@example.test",
            "failure": {"error_code": "email_code_timeout", "retryable": True},
        })
        self.assertEqual(same, incident_id)
        incident = self.store.incident(incident_id)
        assert incident is not None
        self.assertEqual(incident["first_node_code"], "free_email_otp_wait")
        self.assertEqual(len(incident["events"]), 2)
        self.assertEqual(incident["integrity_status"], "verified")
        self.assertNotIn("private", self.store.export([incident_id], "markdown"))
        self.assertNotIn("a@example.test", self.store.export([incident_id], "json"))

    def test_diagnostic_write_failure_is_visible_in_health(self) -> None:
        with patch.object(self.store, "_record", side_effect=sqlite3.OperationalError("locked")):
            with self.assertRaises(sqlite3.OperationalError):
                self.store.record({"level": "error", "outcome": "error", "node_code": "write_test"})
        health = self.store.health()
        self.assertEqual(health["write_failures"], 1)
        self.assertEqual(health["write_status"], "degraded")
        self.assertEqual(health["storage_status"], "degraded")
        self.assertEqual(health["last_write_failure"], "operation=record;error=OperationalError")


    def test_first_business_failure_survives_success_and_later_bare_failure(self) -> None:
        incident_id = self.store.record({
            "event_id": "first-structured", "task_id": "first-failure-order",
            "level": "error", "outcome": "error", "node_code": "proxy_connect",
            "node_label": "代理连接", "failure": {"error_code": "proxy_connect_timeout", "retryable": True},
        })
        self.store.record({
            "event_id": "later-success", "task_id": "first-failure-order",
            "level": "info", "outcome": "success", "node_code": "registration_complete",
        })
        self.store.record({
            "event_id": "later-started", "task_id": "first-failure-order",
            "level": "info", "outcome": "started", "node_code": "retry_started",
        })
        self.store.record({
            "event_id": "later-bare-failure", "task_id": "first-failure-order",
            "level": "error", "outcome": "failed", "node_code": "different_failure",
        })

        incident = self.store.incident(incident_id)
        assert incident is not None
        self.assertEqual(incident["first_node_code"], "proxy_connect")
        self.assertEqual(incident["first_error_code"], "proxy_connect_timeout")
        self.assertTrue(incident["retryable"])
        self.assertEqual(incident["event_count"], 4)

    def test_explicit_success_updates_final_status_without_replacing_first_failure(self) -> None:
        incident_id = self.store.record({
            "event_id": "failed-attempt", "task_id": "eventual-success",
            "level": "error", "outcome": "error", "node_code": "proxy_connect",
            "failure": {"error_code": "proxy_connect_timeout", "retryable": True},
        })
        self.store.record({
            "event_id": "successful-retry", "task_id": "eventual-success",
            "level": "success", "outcome": "success", "node_code": "registration_complete",
        })

        incident = self.store.incident(incident_id)
        assert incident is not None
        self.assertEqual(incident["status"], "success")
        self.assertEqual(incident["outcome"], "success")
        self.assertEqual(incident["first_node_code"], "proxy_connect")
        self.assertEqual(incident["first_error_code"], "proxy_connect_timeout")

    def test_bare_first_failure_is_enriched_by_same_node_structured_event(self) -> None:
        incident_id = self.store.record({
            "event_id": "bare-first", "task_id": "bare-first-task",
            "level": "error", "outcome": "error", "node_code": "mailbox_fetch",
        })
        self.store.record({
            "event_id": "structured-later", "task_id": "bare-first-task",
            "level": "error", "outcome": "failed", "node_code": "mailbox_fetch",
            "failure": {"error_code": "mailbox_timeout", "retryable": False},
        })

        incident = self.store.incident(incident_id)
        assert incident is not None
        self.assertEqual(incident["first_node_code"], "mailbox_fetch")
        self.assertEqual(incident["first_error_code"], "mailbox_timeout")
        self.assertFalse(incident["retryable"])
        self.assertEqual(incident["failure"], {"error_code": "mailbox_timeout", "retryable": False})

    def test_realtime_failure_map_merges_only_missing_same_node_fields(self) -> None:
        incident_id = self.store.record({
            "event_id": "partial-first", "task_id": "partial-map-task",
            "level": "error", "outcome": "error", "node_code": "proxy_connect",
            "failure": {"error_code": "original_error", "retryable": False},
        })
        self.store.record({
            "event_id": "partial-followup", "task_id": "partial-map-task",
            "level": "error", "outcome": "failed", "node_code": "proxy_connect",
            "failure": {
                "error_code": "replacement_error", "retryable": True,
                "http_status": 403, "technical_summary": "代理拒绝",
            },
        })

        incident = self.store.incident(incident_id)
        assert incident is not None
        self.assertEqual(incident["first_error_code"], "original_error")
        self.assertFalse(incident["retryable"])
        self.assertEqual(incident["failure"], {
            "error_code": "original_error",
            "retryable": False,
            "http_status": 403,
            "technical_summary": "代理拒绝",
        })

    def test_cleanup_workflow_and_outcome_are_excluded_from_root_cause(self) -> None:
        incident_id = self.store.record({
            "event_id": "cleanup-neutral", "task_id": "cleanup-neutral-task",
            "level": "warn", "outcome": "cleanup_failed", "workflow": "cleanup",
            "node_code": "proxy_health", "failure": {"error_code": "health_write_failed"},
        })
        self.store.record({
            "event_id": "cleanup-business", "task_id": "cleanup-neutral-task",
            "level": "error", "outcome": "failed", "workflow": "register",
            "node_code": "oauth_callback", "failure": {"error_code": "callback_timeout"},
        })

        incident = self.store.incident(incident_id)
        assert incident is not None
        self.assertEqual(incident["first_node_code"], "oauth_callback")
        self.assertEqual(incident["root_cause_event_id"], "cleanup-business")

    def test_startup_rebuild_restores_summary_without_changing_event_hashes(self) -> None:
        incident_id = self.store.record({
            "event_id": "rebuild-root", "task_id": "rebuild-task",
            "level": "error", "outcome": "error", "node_code": "oauth_callback",
            "node_label": "OAuth 回调", "failure": {"error_code": "callback_timeout", "retryable": True},
        })
        with self.store._connection() as db:
            before = db.execute(
                "SELECT event_hash FROM diagnostic_events WHERE incident_id=?",
                (incident_id,),
            ).fetchone()[0]
            db.execute(
                "UPDATE diagnostic_incidents SET first_node_code='', first_node_label='', first_error_code='', retryable=0, failure_json='{}', event_count=0",
            )

        restarted = DiagnosticStore(Path(self.temp_dir.name))
        incident = restarted.incident(incident_id)
        assert incident is not None
        self.assertEqual(incident["first_node_code"], "oauth_callback")
        self.assertEqual(incident["first_error_code"], "callback_timeout")
        self.assertTrue(incident["retryable"])
        self.assertEqual(incident["event_count"], 1)
        with restarted._connection() as db:
            after = db.execute(
                "SELECT event_hash FROM diagnostic_events WHERE incident_id=?",
                (incident_id,),
            ).fetchone()[0]
        self.assertEqual(before, after)

    def test_startup_rebuild_prefers_earliest_structured_failure(self) -> None:
        incident_id = self.store.record({
            "event_id": "legacy-bare", "task_id": "legacy-rebuild",
            "level": "error", "outcome": "failed", "node_code": "legacy_unknown",
        })
        self.store.record({
            "event_id": "structured-root", "task_id": "legacy-rebuild",
            "level": "error", "outcome": "failed", "node_code": "oauth_callback",
            "node_label": "OAuth 回调",
            "failure": {"error_code": "callback_timeout", "retryable": False},
        })

        restarted = DiagnosticStore(Path(self.temp_dir.name))
        incident = restarted.incident(incident_id)
        assert incident is not None
        self.assertEqual(incident["first_node_code"], "oauth_callback")
        self.assertEqual(incident["first_error_code"], "callback_timeout")
        self.assertFalse(incident["retryable"])

    def test_realtime_append_keeps_earliest_bare_node_over_later_structured_node(self) -> None:
        incident_id = self.store.record({
            "event_id": "realtime-bare", "task_id": "realtime-order",
            "level": "error", "outcome": "failed", "node_code": "legacy_unknown",
        })
        self.store.record({
            "event_id": "realtime-structured", "task_id": "realtime-order",
            "level": "error", "outcome": "failed", "node_code": "oauth_callback",
            "failure": {"error_code": "callback_timeout", "retryable": True},
        })

        incident = self.store.incident(incident_id)
        assert incident is not None
        self.assertEqual(incident["first_node_code"], "legacy_unknown")
        self.assertEqual(incident["first_error_code"], "")
        self.assertFalse(incident["retryable"])

    def test_realtime_append_enriches_bare_first_node_only(self) -> None:
        incident_id = self.store.record({
            "event_id": "realtime-bare-same", "task_id": "realtime-same-node",
            "level": "error", "outcome": "failed", "node_code": "oauth_callback",
        })
        self.store.record({
            "event_id": "realtime-other", "task_id": "realtime-same-node",
            "level": "error", "outcome": "failed", "node_code": "mailbox_fetch",
            "failure": {"error_code": "mailbox_timeout", "retryable": False},
        })
        self.store.record({
            "event_id": "realtime-same", "task_id": "realtime-same-node",
            "level": "error", "outcome": "failed", "node_code": "oauth_callback",
            "node_label": "OAuth 回调",
            "failure": {"error_code": "callback_timeout", "retryable": True},
        })

        incident = self.store.incident(incident_id)
        assert incident is not None
        self.assertEqual(incident["first_node_code"], "oauth_callback")
        self.assertEqual(incident["first_node_label"], "OAuth 回调")
        self.assertEqual(incident["first_error_code"], "callback_timeout")
        self.assertTrue(incident["retryable"])

    def test_realtime_business_failure_repairs_legacy_cleanup_root(self) -> None:
        incident_id = self.store.record({
            "event_id": "legacy-cleanup-root", "task_id": "legacy-cleanup-root-task",
            "level": "error", "outcome": "error", "node_code": "browser_cleanup",
            "failure": {"error_code": "cleanup_failed", "retryable": True},
        })
        # Simulate the pre-migration denormalized summary that incorrectly
        # promoted a cleanup error to the incident root.
        with self.store._connection() as db:
            db.execute(
                "UPDATE diagnostic_incidents SET first_node_code='browser_cleanup', "
                "first_node_label='浏览器清理', first_error_code='cleanup_failed', "
                "retryable=1, failure_json=? WHERE incident_id=?",
                ('{"error_code":"cleanup_failed","retryable":true}', incident_id),
            )

        self.store.record({
            "event_id": "legacy-cleanup-business", "task_id": "legacy-cleanup-root-task",
            "level": "error", "outcome": "error", "node_code": "oauth_callback",
            "node_label": "OAuth 回调",
            "failure": {"error_code": "callback_timeout", "retryable": False},
        })

        incident = self.store.incident(incident_id)
        assert incident is not None
        self.assertEqual(incident["first_node_code"], "oauth_callback")
        self.assertEqual(incident["first_error_code"], "callback_timeout")
        self.assertFalse(incident["retryable"])

    def test_startup_rebuild_clears_cleanup_only_legacy_root(self) -> None:
        incident_id = self.store.record({
            "event_id": "cleanup-only-legacy", "task_id": "cleanup-only-task",
            "level": "error", "outcome": "error", "node_code": "browser_cleanup",
            "failure": {"error_code": "cleanup_failed", "retryable": True},
        })
        with self.store._connection() as db:
            db.execute(
                "UPDATE diagnostic_incidents SET first_node_code='browser_cleanup', "
                "first_node_label='浏览器清理', first_error_code='cleanup_failed', "
                "retryable=1, failure_json=? WHERE incident_id=?",
                ('{"error_code":"cleanup_failed","retryable":true}', incident_id),
            )

        restarted = DiagnosticStore(Path(self.temp_dir.name))
        incident = restarted.incident(incident_id)
        assert incident is not None
        self.assertEqual(incident["first_node_code"], "")
        self.assertEqual(incident["first_error_code"], "")
        self.assertFalse(incident["retryable"])

    def test_realtime_info_touch_clears_cleanup_only_legacy_root(self) -> None:
        incident_id = self.store.record({
            "event_id": "cleanup-only-touch", "task_id": "cleanup-only-touch-task",
            "level": "error", "outcome": "error", "node_code": "browser_cleanup",
            "failure": {"error_code": "cleanup_failed", "retryable": True},
        })
        with self.store._connection() as db:
            db.execute(
                "UPDATE diagnostic_incidents SET first_node_code='browser_cleanup', "
                "first_node_label='浏览器清理', first_error_code='cleanup_failed', "
                "retryable=1, failure_json=? WHERE incident_id=?",
                ('{"error_code":"cleanup_failed","retryable":true}', incident_id),
            )

        self.store.record({
            "event_id": "cleanup-only-touch-info", "task_id": "cleanup-only-touch-task",
            "level": "info", "outcome": "info", "node_code": "browser_cleanup",
        })
        incident = self.store.incident(incident_id)
        assert incident is not None
        self.assertEqual(incident["first_node_code"], "")
        self.assertEqual(incident["first_error_code"], "")

    def test_terminal_success_and_partial_outcomes_survive_lifecycle_info(self) -> None:
        success_id = self.store.record({
            "event_id": "terminal-success", "task_id": "terminal-success-task",
            "level": "success", "outcome": "success", "node_code": "registration_complete",
        })
        self.store.record({
            "event_id": "success-cleanup-info", "task_id": "terminal-success-task",
            "level": "info", "outcome": "info", "node_code": "browser_cleanup",
        })
        partial_id = self.store.record({
            "event_id": "terminal-partial", "task_id": "terminal-partial-task",
            "level": "info", "outcome": "partial", "node_code": "free_plan_check",
        })
        self.store.record({
            "event_id": "partial-cleanup-info", "task_id": "terminal-partial-task",
            "level": "info", "outcome": "info", "node_code": "free_cleanup",
        })

        success = self.store.incident(success_id)
        partial = self.store.incident(partial_id)
        assert success is not None and partial is not None
        self.assertEqual((success["status"], success["outcome"]), ("success", "success"))
        self.assertEqual((partial["status"], partial["outcome"]), ("partial", "partial"))

    def test_startup_rebuild_uses_earliest_structured_node_when_bare_precedes_it(self) -> None:
        incident_id = self.store.record({
            "event_id": "legacy-bare-same-node", "task_id": "legacy-same-node-rebuild",
            "level": "error", "outcome": "failed", "node_code": "oauth_callback",
        })
        self.store.record({
            "event_id": "different-structured", "task_id": "legacy-same-node-rebuild",
            "level": "error", "outcome": "failed", "node_code": "mailbox_fetch",
            "failure": {"error_code": "mailbox_timeout", "retryable": False},
        })
        self.store.record({
            "event_id": "same-node-structured", "task_id": "legacy-same-node-rebuild",
            "level": "error", "outcome": "failed", "node_code": "oauth_callback",
            "node_label": "OAuth 回调",
            "failure": {"error_code": "callback_timeout", "retryable": True},
        })
        with self.store._connection() as db:
            db.execute(
                "UPDATE diagnostic_incidents SET first_node_code='mailbox_fetch', "
                "first_error_code='mailbox_timeout', retryable=0, failure_json='{}' "
                "WHERE incident_id=?",
                (incident_id,),
            )

        restarted = DiagnosticStore(Path(self.temp_dir.name))
        incident = restarted.incident(incident_id)
        assert incident is not None
        self.assertEqual(incident["first_node_code"], "mailbox_fetch")
        self.assertEqual(incident["first_error_code"], "mailbox_timeout")
        self.assertFalse(incident["retryable"])

    def test_startup_rebuild_audits_tampered_chain_without_repairing_summary(self) -> None:
        incident_id = self.store.record({
            "event_id": "tampered-root", "task_id": "tampered-rebuild",
            "level": "error", "outcome": "failed", "node_code": "original_node",
            "failure": {"error_code": "original_error", "retryable": True},
        })
        with self.store._connection() as db:
            db.execute(
                "UPDATE diagnostic_incidents SET first_node_code='keep_existing' WHERE incident_id=?",
                (incident_id,),
            )
            db.execute(
                "UPDATE diagnostic_events SET node_label='tampered' WHERE event_id='tampered-root'",
            )

        restarted = DiagnosticStore(Path(self.temp_dir.name))
        with restarted._connection() as db:
            incident = db.execute(
                "SELECT first_node_code,integrity_status FROM diagnostic_incidents WHERE incident_id=?",
                (incident_id,),
            ).fetchone()
            audits = db.execute(
                "SELECT detail FROM diagnostic_access_audit WHERE action='rebuild_incident_summaries'",
            ).fetchall()
        self.assertEqual(tuple(incident), ("keep_existing", "failed"))
        self.assertTrue(any("integrity_skipped=1" in str(row[0]) for row in audits))

    def test_append_after_tamper_keeps_existing_summary(self) -> None:
        incident_id = self.store.record({
            "event_id": "tamper-append-root", "task_id": "tamper-append",
            "level": "error", "outcome": "failed", "node_code": "original_node",
            "failure": {"error_code": "original_error", "retryable": True},
        })
        with self.store._connection() as db:
            db.execute("UPDATE diagnostic_events SET node_label='tampered' WHERE event_id='tamper-append-root'")
            db.execute("UPDATE diagnostic_incidents SET first_node_label='original label' WHERE incident_id=?", (incident_id,))

        self.store.record({
            "event_id": "tamper-append-followup", "task_id": "tamper-append",
            "level": "error", "outcome": "failed", "node_code": "followup_node",
            "failure": {"error_code": "followup_error", "retryable": False},
        })
        incident = self.store.incident(incident_id)
        assert incident is not None
        self.assertEqual(incident["first_node_code"], "original_node")
        self.assertEqual(incident["first_node_label"], "original label")
        self.assertEqual(incident["first_error_code"], "original_error")
        self.assertTrue(incident["retryable"])
        self.assertEqual(incident["integrity_status"], "failed")

    def test_retained_chain_suffix_remains_unverified_not_tampered(self) -> None:
        incident_id = self.store.record({
            "event_id": "retained-first", "task_id": "retained-chain",
            "level": "error", "outcome": "failed", "node_code": "first_node",
        })
        self.store.record({
            "event_id": "retained-second", "task_id": "retained-chain",
            "level": "error", "outcome": "failed", "node_code": "second_node",
        })
        with self.store._connection() as db:
            db.execute("DELETE FROM diagnostic_events WHERE event_id='retained-first'")
            db.execute(
                "UPDATE diagnostic_incidents SET integrity_status='unverified',event_count=1 WHERE incident_id=?",
                (incident_id,),
            )

        restarted = DiagnosticStore(Path(self.temp_dir.name))
        incident = restarted.incident(incident_id)
        assert incident is not None
        self.assertEqual(incident["integrity_status"], "unverified")

    def test_unverified_rebuild_repairs_event_count_without_touching_summary_or_hash(self) -> None:
        incident_id = self.store.record({
            "event_id": "retained-count-first", "task_id": "retained-count",
            "level": "error", "outcome": "failed", "node_code": "first_node",
            "failure": {"error_code": "first_error", "retryable": True},
        })
        self.store.record({
            "event_id": "retained-count-second", "task_id": "retained-count",
            "level": "error", "outcome": "failed", "node_code": "second_node",
        })
        with self.store._connection() as db:
            db.execute("DELETE FROM diagnostic_events WHERE event_id='retained-count-first'")
            db.execute(
                "UPDATE diagnostic_incidents SET integrity_status='unverified',event_count=99,first_node_code='preserved_root',first_error_code='preserved_error' WHERE incident_id=?",
                (incident_id,),
            )
            before_hash = db.execute(
                "SELECT event_hash FROM diagnostic_events WHERE event_id='retained-count-second'",
            ).fetchone()[0]

        restarted = DiagnosticStore(Path(self.temp_dir.name))
        incident = restarted.incident(incident_id)
        assert incident is not None
        self.assertEqual(incident["event_count"], 1)
        self.assertEqual(incident["integrity_status"], "unverified")
        self.assertEqual(incident["first_node_code"], "preserved_root")
        self.assertEqual(incident["first_error_code"], "preserved_error")
        with restarted._connection() as db:
            after_hash = db.execute(
                "SELECT event_hash FROM diagnostic_events WHERE event_id='retained-count-second'",
            ).fetchone()[0]
        self.assertEqual(before_hash, after_hash)

    def test_append_after_fully_pruned_chain_remains_unverified(self) -> None:
        incident_id = self.store.record({
            "event_id": "fully-pruned-append-root", "task_id": "fully-pruned-append",
            "level": "error", "outcome": "failed", "node_code": "original_node",
            "failure": {"error_code": "original_error", "retryable": True},
        })
        with self.store._connection() as db:
            db.execute("DELETE FROM diagnostic_events WHERE incident_id=?", (incident_id,))
            db.execute(
                "UPDATE diagnostic_incidents SET integrity_status='unverified',event_count=0 WHERE incident_id=?",
                (incident_id,),
            )

        self.store.record({
            "event_id": "fully-pruned-append-followup", "task_id": "fully-pruned-append",
            "level": "error", "outcome": "failed", "node_code": "followup_node",
            "failure": {"error_code": "followup_error", "retryable": False},
        })
        incident = self.store.incident(incident_id)
        assert incident is not None
        self.assertEqual(incident["integrity_status"], "unverified")
        self.assertEqual(incident["first_node_code"], "")
        self.assertEqual(incident["first_error_code"], "")

    def test_startup_rebuild_recovers_structured_failure_with_neutral_outcome(self) -> None:
        incident_id = self.store.record({
            "event_id": "neutral-structured-failure", "task_id": "neutral-structured",
            "level": "info", "outcome": "info", "node_code": "proxy_connect",
            "failure": {"error_code": "proxy_connect_failed", "retryable": True},
        })
        with self.store._connection() as db:
            db.execute(
                "UPDATE diagnostic_incidents SET first_node_code='',first_error_code='',retryable=0,failure_json='{}' WHERE incident_id=?",
                (incident_id,),
            )

        restarted = DiagnosticStore(Path(self.temp_dir.name))
        incident = restarted.incident(incident_id)
        assert incident is not None
        self.assertEqual(incident["first_node_code"], "proxy_connect")
        self.assertEqual(incident["first_error_code"], "proxy_connect_failed")
        self.assertTrue(incident["retryable"])

    def test_fully_pruned_event_chain_remains_unverified_after_restart(self) -> None:
        incident_id = self.store.record({
            "event_id": "fully-pruned", "task_id": "fully-pruned-chain",
            "level": "error", "outcome": "failed", "node_code": "first_node",
        })
        with self.store._connection() as db:
            db.execute("DELETE FROM diagnostic_events WHERE incident_id=?", (incident_id,))
            db.execute(
                "UPDATE diagnostic_incidents SET integrity_status='unverified',event_count=0 WHERE incident_id=?",
                (incident_id,),
            )

        restarted = DiagnosticStore(Path(self.temp_dir.name))
        incident = restarted.incident(incident_id)
        assert incident is not None
        self.assertEqual(incident["integrity_status"], "unverified")

    def test_empty_tampered_chain_keeps_failed_integrity_status(self) -> None:
        incident_id = self.store.record({
            "event_id": "empty-failed-chain", "task_id": "empty-failed",
            "level": "error", "outcome": "error", "node_code": "first_node",
        })
        with self.store._connection() as db:
            db.execute("DELETE FROM diagnostic_events WHERE incident_id=?", (incident_id,))
            db.execute(
                "UPDATE diagnostic_incidents SET integrity_status='failed',event_count=0 WHERE incident_id=?",
                (incident_id,),
            )
        self.assertEqual(self.store.incident(incident_id)["integrity_status"], "failed")

    def test_strict_transport_redaction(self) -> None:
        incident_id = self.store.record({
            "level": "error", "outcome": "error", "task_id": "redact",
            "node_code": "oauth", "message": "Authorization: Bearer abcdef123456 user=a@example.test phone=13800138000",
        })
        content = self.store.export([incident_id], "json")
        self.assertNotIn("abcdef123456", content)
        self.assertNotIn("a@example.test", content)
        self.assertNotIn("13800138000", content)

    def test_failure_and_transport_maps_use_scalar_allowlists(self) -> None:
        incident_id = self.store.record({
            "level": "error", "outcome": "error", "task_id": "allowlist",
            "node_code": "proxy_preflight",
            "failure": {
                "error_code": "proxy_connect_failed",
                "technical_summary": "连接失败",
                "retryable": True,
                "sample_id": "sample-123",
                "raw_body": "access_token=should-not-persist",
                "headers": {"Authorization": "Bearer should-not-persist"},
                "response_body": ["secret-body"],
            },
            "transport": {
                "failure_count": 2,
                "total_count": 3,
                "target_domain": "chatgpt.com",
                "proxy_fingerprints": "sha256:abc123",
                "nodes": ["proxy_connect", "proxy_auth"],
                "headers": {"Cookie": "should-not-persist"},
                "raw_body": "should-not-persist",
            },
        })
        incident = self.store.incident(incident_id)
        assert incident is not None
        event = incident["events"][0]
        self.assertEqual(event["failure"], {
            "error_code": "proxy_connect_failed",
            "technical_summary": "连接失败",
            "retryable": True,
            "sample_id": "sample-123",
        })
        self.assertEqual(event["transport"], {
            "failure_count": 2,
            "total_count": 3,
            "target_domain": "chatgpt.com",
            "proxy_fingerprints": "sha256:abc123",
            "nodes": ["proxy_connect", "proxy_auth"],
        })
        exported = self.store.export([incident_id], "json")
        self.assertNotIn("should-not-persist", exported)

    def test_legacy_failure_json_is_projected_when_read(self) -> None:
        incident_id = self.store.record({
            "level": "error", "outcome": "error", "task_id": "legacy-map",
            "node_code": "oauth", "failure": {"error_code": "old_error"},
        })
        with self.store._connection() as db:
            db.execute(
                "UPDATE diagnostic_events SET failure_json=? WHERE incident_id=?",
                ('{"error_code":"old_error","raw_body":"private"}', incident_id),
            )
        # The event hash is intentionally now invalid; read projection still
        # must never expose the untrusted legacy field.
        incident = self.store.incident(incident_id)
        assert incident is not None
        self.assertEqual(incident["events"][0]["failure"], {"error_code": "old_error"})
        self.assertNotIn("private", self.store.export([incident_id], "json"))

    def test_direct_record_redacts_labels_and_rejects_untrusted_timestamps(self) -> None:
        incident_id = self.store.record({
            "level": "error", "outcome": "error", "task_id": "direct-redaction",
            "node_code": "oauth", "node_label": "token=private https://user:pass@proxy.test/x",
            "occurred_at": "token=private",
        })
        incident = self.store.incident(incident_id)
        assert incident is not None
        rendered = self.store.export([incident_id], "json")
        self.assertNotIn("private", rendered)
        self.assertNotIn("user:pass", rendered)
        self.assertRegex(incident["events"][0]["occurred_at"], r"^\d{4}-\d{2}-\d{2}T")

    def test_subject_display_rejects_credential_looking_values(self) -> None:
        incident_id = self.store.record({
            "level": "error", "outcome": "error", "task_id": "subject-redaction",
            "node_code": "oauth", "subject_kind": "email",
            "subject_display": "user@example.test?token=private",
        })
        incident = self.store.incident(incident_id)
        assert incident is not None
        self.assertEqual(incident["subject_display"], "已脱敏账号")

    def test_search_by_email_uses_hmac_and_delete_does_not_touch_business_data(self) -> None:
        incident_id = self.store.record({
            "level": "error", "outcome": "error", "task_id": "free-task-1",
            "chain": "free", "driver": "camoufox", "email": "A@example.test",
            "node_code": "free_camoufox_signup", "message": "signup failed",
        })
        self.assertEqual(self.store.search({"subject": "a@example.test"})[0]["incident_id"], incident_id)
        self.assertEqual(self.store.delete([incident_id]), 1)
        self.assertIsNone(self.store.incident(incident_id))
        self.assertEqual(self.store.health()["incidents"], 0)

    def test_date_search_and_terminal_cleanup_keep_failure_status(self) -> None:
        incident_id = self.store.record({
            "event_id": "date-failure", "level": "error", "outcome": "error", "task_id": "date-task",
            "occurred_at": "2026-08-25T08:00:00Z", "node_code": "oauth_callback",
            "failure": {"http_status": 401, "provider_code": "invalid_session"},
        })
        self.store.record({
            "event_id": "date-cleanup", "level": "info", "outcome": "info", "task_id": "date-task",
            "occurred_at": "2026-08-25T08:00:01Z", "node_code": "browser_cleanup",
        })
        result = self.store.incident(incident_id)
        assert result is not None
        self.assertEqual(result["status"], "failed")
        self.assertEqual(self.store.search({"date": "2026-08-25"})[0]["incident_id"], incident_id)
        self.assertIn("401", self.store.export([incident_id], "json"))

    def test_clear_all_only_clears_diagnostic_index(self) -> None:
        self.store.record({"level": "error", "outcome": "error", "task_id": "T1", "node_code": "unexpected", "message": "x"})
        self.store.record({"level": "error", "outcome": "error", "task_id": "T2", "node_code": "unexpected", "message": "y"})
        self.assertEqual(self.store.clear(), 2)
        self.assertEqual(self.store.health()["incidents"], 0)
        self.assertTrue(Path(self.temp_dir.name).exists())

    def test_new_batch_gets_new_incident_but_repeated_event_is_idempotent(self) -> None:
        first = self.store.record({
            "event_id": "event-1", "task_id": "same-task", "batch_id": "batch-1",
            "level": "error", "outcome": "error", "node_code": "email_otp",
        })
        self.assertEqual(self.store.record({
            "event_id": "event-1", "task_id": "same-task", "batch_id": "batch-1",
            "level": "error", "outcome": "error", "node_code": "email_otp",
        }), first)
        second = self.store.record({
            "event_id": "event-2", "task_id": "same-task", "batch_id": "batch-2",
            "level": "error", "outcome": "error", "node_code": "email_otp_retry",
        })
        self.assertNotEqual(first, second)
        self.assertEqual(self.store.incident(first)["event_count"], 1)

    def test_cleanup_failure_does_not_replace_business_root_cause_and_tamper_is_detected(self) -> None:
        incident_id = self.store.record({
            "event_id": "business", "task_id": "task-cleanup", "batch_id": "batch",
            "level": "error", "outcome": "error", "node_code": "oauth_callback",
            "node_label": "OAuth 回调",
        })
        self.store.record({
            "event_id": "cleanup", "task_id": "task-cleanup", "batch_id": "batch",
            "level": "error", "outcome": "error", "node_code": "browser_cleanup",
            "node_label": "浏览器清理",
        })
        self.assertEqual(self.store.incident(incident_id)["first_node_code"], "oauth_callback")
        with self.store._connection() as db:
            db.execute("UPDATE diagnostic_events SET node_label='被篡改' WHERE event_id='business'")
        self.assertEqual(self.store.incident(incident_id)["integrity_status"], "failed")

    def test_deleted_incident_id_is_tombstoned(self) -> None:
        incident_id = self.store.record({"event_id": "tombstone", "level": "error", "outcome": "error", "node_code": "x"})
        self.assertEqual(self.store.delete([incident_id]), 1)
        replacement = self.store.record({"event_id": "replacement", "level": "error", "outcome": "error", "node_code": "x"})
        self.assertNotEqual(incident_id, replacement)

    def test_retention_prunes_events_and_old_incident_summaries_without_reusing_ids(self) -> None:
        store = DiagnosticStore(Path(self.temp_dir.name) / "retention", event_retention_days=1, incident_retention_days=2)
        incident_id = store.record({
            "event_id": "old-event", "level": "error", "outcome": "error", "task_id": "old-task",
            "occurred_at": "2020-01-01T00:00:00Z", "node_code": "old_node",
        })
        result = store.prune(now="2090-01-04T00:00:00Z")
        self.assertEqual(result["events"], 1)
        self.assertEqual(result["incidents"], 1)
        self.assertIsNone(store.incident(incident_id))
        replacement = store.record({"event_id": "new-event", "level": "error", "outcome": "error", "node_code": "old_node"})
        self.assertNotEqual(incident_id, replacement)


if __name__ == "__main__":
    unittest.main()
