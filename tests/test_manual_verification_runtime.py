from __future__ import annotations

import threading
import time
import unittest

from mac_overrides.manual_verification_runtime import (
    ManualVerificationBroker,
    ManualVerificationError,
    ManualVerificationStopped,
    validate_code,
    wait_with_manual_fallback,
)


class ManualVerificationRuntimeTests(unittest.TestCase):
    def test_open_public_state_never_contains_code(self):
        broker = ManualVerificationBroker()
        public = broker.open("T001", "email_otp", 4)
        self.assertEqual(public["input_kind"], "email_otp")
        self.assertNotIn("code", repr(public))
        broker.submit("T001", "email_otp", 4, "123456")

    def test_submit_is_one_time_and_generation_checked(self):
        broker = ManualVerificationBroker()
        broker.open("T001", "totp", 1)
        with self.assertRaisesRegex(ManualVerificationError, "当前任务提示"):
            broker.submit("T001", "totp", 0, "123456")
        broker.submit("T001", "totp", 1, "123456")
        with self.assertRaises(ManualVerificationError):
            broker.submit("T001", "totp", 1, "123456")

    def test_wait_consumes_code_and_stop_cancels(self):
        broker = ManualVerificationBroker(default_window_seconds=5)
        broker.open("T001", "sms_otp", 1)
        stop = threading.Event()
        result = []

        def waiter():
            result.append(broker.wait("T001", "sms_otp", 1, stop_event=stop))

        thread = threading.Thread(target=waiter)
        thread.start()
        time.sleep(0.02)
        broker.submit("T001", "sms_otp", 1, "654321")
        thread.join(1)
        self.assertEqual(result, ["654321"])

        broker.open("T002", "sms_otp", 1)
        stop.set()
        with self.assertRaises(ManualVerificationStopped):
            broker.wait("T002", "sms_otp", 1, stop_event=stop)

    def test_code_shapes_are_bounded(self):
        self.assertEqual(validate_code("totp", "123456"), "123456")
        self.assertEqual(validate_code("email_otp", "1234"), "1234")
        for kind, code in (("totp", "12345"), ("email_otp", "12"), ("sms_otp", "abc123")):
            with self.assertRaises(ManualVerificationError):
                validate_code(kind, code)

    def test_late_submission_after_expiry_is_410_even_after_public_prune(self):
        now = [100.0]
        broker = ManualVerificationBroker(clock=lambda: now[0], default_window_seconds=1)
        broker.open("T-expired", "email_otp", 3)
        now[0] = 102.0

        self.assertEqual(broker.public("T-expired"), {})
        with self.assertRaises(ManualVerificationError) as raised:
            broker.submit("T-expired", "email_otp", 3, "123456")
        self.assertEqual(raised.exception.status, 410)

        with self.assertRaises(ManualVerificationError) as raised:
            broker.submit("T-expired", "email_otp", 2, "123456")
        self.assertEqual(raised.exception.status, 409)

    def test_stopped_and_consumed_prompts_keep_safe_late_status(self):
        broker = ManualVerificationBroker()
        broker.open("T-stopped", "sms_otp", 1)
        broker.cancel_task("T-stopped")
        with self.assertRaises(ManualVerificationError) as raised:
            broker.submit("T-stopped", "sms_otp", 1, "123456")
        self.assertEqual(raised.exception.status, 410)

        broker.open("T-consumed", "totp", 1)
        broker.submit("T-consumed", "totp", 1, "123456")
        with self.assertRaises(ManualVerificationError) as raised:
            broker.submit("T-consumed", "totp", 1, "654321")
        self.assertEqual(raised.exception.status, 409)

    def test_superseded_prompt_is_stale_not_expired(self):
        broker = ManualVerificationBroker()
        broker.open("T-superseded", "email_otp", 1)
        broker.open("T-superseded", "email_otp", 2)
        with self.assertRaises(ManualVerificationError) as raised:
            broker.submit("T-superseded", "email_otp", 1, "123456")
        self.assertEqual(raised.exception.code, "stale_generation")
        self.assertEqual(raised.exception.status, 409)

    def test_invalid_automatic_code_falls_back_to_manual_prompt(self):
        broker = ManualVerificationBroker(default_window_seconds=2)
        result = []

        def run():
            result.append(
                wait_with_manual_fallback(
                    lambda: "not-a-code",
                    broker=broker,
                    task_id="T-auto-invalid",
                    input_kind="email_otp",
                    generation=1,
                    automatic_timeout_seconds=1,
                    manual_timeout_seconds=2,
                )
            )

        thread = threading.Thread(target=run)
        thread.start()
        deadline = time.time() + 1
        while time.time() < deadline and not broker.public("T-auto-invalid"):
            time.sleep(0.01)
        prompt = broker.public("T-auto-invalid")
        self.assertTrue(prompt.get("can_submit"))
        broker.submit("T-auto-invalid", "email_otp", 1, "123456")
        thread.join(1)
        self.assertFalse(thread.is_alive())
        self.assertEqual(result, ["123456"])

    def test_manual_submission_wins_when_it_arrives_before_late_automatic_code(self):
        broker = ManualVerificationBroker(default_window_seconds=3)
        release_automatic = threading.Event()
        result = []

        def automatic_wait():
            release_automatic.wait(2)
            return "111111"

        def run():
            result.append(
                wait_with_manual_fallback(
                    automatic_wait,
                    broker=broker,
                    task_id="T-race",
                    input_kind="sms_otp",
                    generation=1,
                    automatic_timeout_seconds=1,
                    manual_timeout_seconds=3,
                )
            )

        thread = threading.Thread(target=run)
        thread.start()
        deadline = time.time() + 1.5
        while time.time() < deadline and not broker.public("T-race"):
            time.sleep(0.01)
        self.assertTrue(broker.public("T-race").get("can_submit"))
        broker.submit("T-race", "sms_otp", 1, "222222")
        release_automatic.set()
        thread.join(1)
        self.assertFalse(thread.is_alive())
        self.assertEqual(result, ["222222"])

    def test_automatic_unmatched_callback_runs_once_before_manual_prompt(self):
        broker = ManualVerificationBroker(default_window_seconds=3)
        events = []
        result = []

        def run():
            result.append(
                wait_with_manual_fallback(
                    lambda: "not-a-code",
                    broker=broker,
                    task_id="T-unmatched",
                    input_kind="email_otp",
                    generation=1,
                    automatic_timeout_seconds=1,
                    manual_timeout_seconds=3,
                    on_automatic_unmatched=lambda reason: events.append(("unmatched", reason)),
                    on_manual_opened=lambda prompt: events.append(("manual", prompt["input_kind"])),
                )
            )

        thread = threading.Thread(target=run)
        thread.start()
        deadline = time.time() + 1
        while time.time() < deadline and not broker.public("T-unmatched"):
            time.sleep(0.01)
        prompt = broker.public("T-unmatched")
        self.assertTrue(prompt.get("can_submit"))
        broker.submit("T-unmatched", "email_otp", 1, "123456")
        thread.join(1)
        self.assertEqual(result, ["123456"])
        self.assertEqual([event[0] for event in events], ["unmatched", "manual"])

    def test_manual_submission_before_automatic_timeout_does_not_mark_unmatched(self):
        broker = ManualVerificationBroker(default_window_seconds=3)
        automatic_release = threading.Event()
        events = []
        result = []

        def run():
            result.append(
                wait_with_manual_fallback(
                    lambda: (automatic_release.wait(2), "111111")[1],
                    broker=broker,
                    task_id="T-early-manual",
                    input_kind="email_otp",
                    generation=1,
                    automatic_timeout_seconds=2,
                    manual_timeout_seconds=3,
                    on_automatic_unmatched=lambda reason: events.append(reason),
                )
            )

        thread = threading.Thread(target=run)
        thread.start()
        broker.open("T-early-manual", "email_otp", 1, window_seconds=3)
        broker.submit("T-early-manual", "email_otp", 1, "222222")
        automatic_release.set()
        thread.join(1)
        self.assertEqual(result, ["222222"])
        self.assertEqual(events, [])

    def test_preopened_manual_prompt_notifies_owner_once(self):
        """A UI-opened prompt pauses its owner without duplicate callbacks."""
        broker = ManualVerificationBroker(default_window_seconds=3)
        opened = broker.open("T-preopened", "email_otp", 1, window_seconds=3)
        callback_seen = threading.Event()
        automatic_release = threading.Event()
        callbacks = []
        result = []

        def on_manual_opened(prompt):
            callbacks.append(prompt)
            callback_seen.set()

        def run():
            result.append(
                wait_with_manual_fallback(
                    lambda: (automatic_release.wait(2), "not-a-code")[1],
                    broker=broker,
                    task_id="T-preopened",
                    input_kind="email_otp",
                    generation=1,
                    automatic_timeout_seconds=1,
                    manual_timeout_seconds=3,
                    on_manual_opened=on_manual_opened,
                )
            )

        thread = threading.Thread(target=run)
        thread.start()
        self.assertTrue(callback_seen.wait(1))
        # The same prompt is observed repeatedly while the automatic worker
        # remains blocked; notification must stay one-shot.
        time.sleep(0.05)
        broker.submit("T-preopened", "email_otp", 1, "123456")
        automatic_release.set()
        thread.join(1)

        self.assertFalse(thread.is_alive())
        self.assertEqual(result, ["123456"])
        self.assertEqual(len(callbacks), 1)
        self.assertEqual(callbacks[0]["opened_at"], opened["opened_at"])
        self.assertEqual(callbacks[0]["deadline_at"], opened["deadline_at"])


if __name__ == "__main__":
    unittest.main()
