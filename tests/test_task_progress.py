from __future__ import annotations

import math
import threading
import unittest

from mac_overrides.task_progress import (
    STAGE_GROUPS,
    TaskProgressTracker,
    is_active_progress,
    stage_for_chain_state,
    stage_for_task_status,
)


class FakeClock:
    def __init__(self, value: int = 100) -> None:
        self.value = value

    def __call__(self) -> float:
        return float(self.value)


class TaskProgressTests(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = FakeClock()
        self.tracker = TaskProgressTracker(self.clock)

    def test_task_and_oauth_events_map_to_granular_stages(self):
        self.assertEqual(stage_for_task_status("queued"), "queue_waiting")
        self.assertEqual(stage_for_chain_state("START"), "oauth_create_node")
        self.assertEqual(stage_for_chain_state("CHAT_REQUIREMENTS_READY"), "oauth_authorize_node")
        self.assertEqual(stage_for_chain_state("CONSENT_REQUIRED"), "finalizing_callback")
        self.assertEqual(stage_for_chain_state("CALLBACK_RECEIVED"), "finalizing_token")
        self.assertEqual(stage_for_chain_state("TOKEN_EXCHANGED"), "finalizing_upload")
        self.assertEqual(stage_for_chain_state("PHONE_SEND_REJECTED"), "phone_submitting")
        self.assertEqual(stage_for_chain_state("FAILED"), None)

        self.tracker.observe_task_state("T001", "queued")
        self.clock.value = 110
        self.tracker.observe_task_state("T001", "authorizing")
        self.clock.value = 120
        self.tracker.observe_chain_state("T001", "OAUTH_STARTED")
        self.clock.value = 130
        self.tracker.observe_chain_state("T001", "EMAIL_OTP_REQUIRED")

        progress = self.tracker.progress("T001")
        self.assertEqual(
            {key: progress[key] for key in ("code", "label", "group", "entered_at", "finished_at")},
            {
                "code": "email_code_waiting",
                "label": "等待邮箱验证码",
                "group": "email",
                "entered_at": 130,
                "finished_at": None,
            },
        )
        self.assertEqual(progress["timing"]["elapsed_seconds"], 30)

    def test_repeated_stage_does_not_reset_elapsed_time(self):
        self.tracker.set_stage("T001", "sms_waiting")
        self.clock.value = 145
        changed = self.tracker.set_stage("T001", "sms_waiting")

        self.assertFalse(changed)
        self.assertEqual(self.tracker.progress("T001")["entered_at"], 100)

    def test_queue_and_execution_timing_are_separate_and_freeze(self):
        self.tracker.observe_task_state("T001", "queued")
        self.clock.value = 112
        self.assertTrue(self.tracker.mark_execution_started("T001"))
        self.assertTrue(self.tracker.record_segment("T001", "task_slot_waiting", 12))
        self.clock.value = 142
        self.tracker.observe_task_state("T001", "success")
        self.clock.value = 200

        timing = self.tracker.progress("T001")["timing"]
        self.assertEqual(timing["queued_at"], 100)
        self.assertEqual(timing["execution_started_at"], 112)
        self.assertEqual(timing["queue_elapsed_seconds"], 12)
        self.assertEqual(timing["execution_elapsed_seconds"], 30)
        self.assertEqual(timing["elapsed_seconds"], 42)
        self.assertEqual(timing["segments"][0]["code"], "task_slot_waiting")

    def test_segments_accumulate_without_changing_stage_and_freeze_at_terminal(self):
        self.tracker.set_stage("T001", "phone_submitting")

        self.assertTrue(
            self.tracker.record_segment("T001", "phone_slot_waiting", 0.375)
        )
        self.assertTrue(
            self.tracker.record_segment("T001", "phone_slot_waiting", 0.625)
        )
        self.assertTrue(
            self.tracker.record_segment("T001", "sentinel_refresh", 1.2345)
        )

        progress = self.tracker.progress("T001")
        self.assertEqual(progress["code"], "phone_submitting")
        segments = {row["code"]: row for row in progress["timing"]["segments"]}
        self.assertEqual(segments["phone_slot_waiting"]["visits"], 2)
        self.assertEqual(segments["phone_slot_waiting"]["elapsed_seconds"], 1.0)
        self.assertEqual(segments["sentinel_refresh"]["elapsed_seconds"], 1.234)

        self.tracker.finish("T001")
        frozen = self.tracker.progress("T001")["timing"]["segments"]
        self.assertFalse(
            self.tracker.record_segment("T001", "phone_slot_waiting", 10)
        )
        self.assertEqual(self.tracker.progress("T001")["timing"]["segments"], frozen)

    def test_segments_reject_unknown_codes_and_untracked_tasks(self):
        self.assertFalse(
            self.tracker.record_segment("missing", "protocol_slot_waiting", 1)
        )
        self.tracker.set_stage("T001", "oauth_create_node")
        self.assertFalse(self.tracker.record_segment("T001", "private-value", 1))
        for value in (math.nan, math.inf, -math.inf):
            with self.subTest(value=value):
                self.assertFalse(
                    self.tracker.record_segment(
                        "T001",
                        "protocol_slot_waiting",
                        value,
                    )
                )

    def test_segments_accumulate_atomically_across_threads(self):
        self.tracker.set_stage("T001", "phone_submitting")
        threads = [
            threading.Thread(
                target=self.tracker.record_segment,
                args=("T001", "phone_slot_waiting", 0.01),
            )
            for _ in range(20)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        segment = self.tracker.progress("T001")["timing"]["segments"][0]
        self.assertEqual(segment["visits"], 20)
        self.assertEqual(segment["elapsed_seconds"], 0.2)

    def test_active_progress_can_drive_mailbox_running_state(self):
        self.tracker.set_stage("T001", "phone_acquiring")
        progress = self.tracker.progress("T001")

        self.assertTrue(is_active_progress(progress, "authorizing"))
        self.assertFalse(is_active_progress(progress, "failed"))

        self.tracker.observe_task_state("T001", "success")
        self.assertFalse(is_active_progress(self.tracker.progress("T001"), "success"))

    def test_account_banned_is_terminal_and_freezes_phone_stage(self):
        self.tracker.set_stage("T004", "phone_submitting")
        self.clock.value = 120
        self.tracker.observe_task_state("T004", "account_banned")
        self.clock.value = 140

        self.assertFalse(self.tracker.set_stage("T004", "phone_acquiring"))
        self.assertFalse(is_active_progress(self.tracker.progress("T004"), "account_banned"))
        self.assertEqual(self.tracker.progress("T004")["finished_at"], 120)

    def test_phone_retry_reenters_acquisition_and_terminal_state_freezes(self):
        self.tracker.set_stage("T001", "phone_acquiring")
        self.clock.value = 105
        self.tracker.set_stage("T001", "phone_submitting")
        self.clock.value = 110
        self.tracker.set_stage("T001", "sms_waiting")
        self.clock.value = 140
        self.tracker.set_stage("T001", "phone_acquiring")
        self.clock.value = 155
        self.tracker.observe_task_state("T001", "failed")
        self.clock.value = 200

        self.assertFalse(self.tracker.set_stage("T001", "finalizing_save"))
        progress = self.tracker.progress("T001")
        self.assertEqual(progress["code"], "phone_acquiring")
        self.assertEqual(progress["entered_at"], 140)
        self.assertEqual(progress["finished_at"], 155)
        stages = {row["code"]: row for row in progress["timing"]["stages"]}
        self.assertEqual(stages["phone_acquiring"]["visits"], 2)
        self.assertEqual(stages["phone_acquiring"]["elapsed_seconds"], 20)
        self.assertEqual(progress["timing"]["elapsed_seconds"], 55)

    def test_fake_chain_and_sms_flow_reaches_final_upload(self):
        self.tracker.observe_task_state("T001", "authorizing")
        for state in ("START", "CHAT_REQUIREMENTS_READY", "OAUTH_STARTED", "SENTINEL_READY"):
            self.clock.value += 1
            self.tracker.observe_chain_state("T001", state)
        self.tracker.observe_chain_state("T001", "PHONE_REQUIRED")
        self.tracker.set_stage("T001", "phone_submitting")
        self.tracker.observe_chain_state("T001", "PHONE_OTP_SENT")
        self.tracker.set_stage("T001", "sms_verifying")
        self.tracker.observe_chain_state("T001", "CALLBACK_RECEIVED")
        self.tracker.observe_chain_state("T001", "TOKEN_EXCHANGED")
        self.tracker.set_stage("T001", "finalizing_save")

        progress = self.tracker.progress("T001")
        self.assertEqual(progress["code"], "finalizing_save")
        self.assertEqual(progress["group"], "finalizing")

    def test_runtime_counts_only_active_tasks_and_keeps_failed_progress(self):
        self.tracker.observe_task_state("T001", "queued")
        self.tracker.observe_task_state("T002", "authorizing")
        self.tracker.set_stage("T003", "sms_waiting")
        self.tracker.observe_task_state("T003", "failed")
        runtime = {
            "running": True,
            "tasks": [
                {"task_id": "T001", "status": "queued"},
                {"task_id": "T002", "status": "authorizing"},
                {"task_id": "T003", "status": "failed"},
            ],
        }

        self.tracker.decorate_runtime(runtime)

        self.assertEqual(runtime["stage_counts"], {
            "queue": 1,
            "oauth": 1,
            "free": 0,
            "email": 0,
            "phone": 0,
            "sms": 0,
            "finalizing": 0,
        })
        self.assertEqual(runtime["tasks"][2]["progress"]["code"], "sms_waiting")
        self.assertEqual(set(runtime["stage_counts"]), set(STAGE_GROUPS))

        runtime["running"] = False
        self.tracker.decorate_runtime(runtime)
        self.assertTrue(all(value == 0 for value in runtime["stage_counts"].values()))

    def test_reset_removes_previous_run_progress(self):
        self.tracker.set_stage("T001", "oauth_create_node")
        self.tracker.reset()
        self.assertIsNone(self.tracker.progress("T001"))


if __name__ == "__main__":
    unittest.main()
