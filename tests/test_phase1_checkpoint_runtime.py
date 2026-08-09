from __future__ import annotations

import base64
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from mac_overrides.phase1_checkpoint_runtime import (
    CheckpointDisabled,
    CheckpointLeaseLost,
    KeychainOperationStopped,
    Phase1CheckpointStore,
    SecurityKeyProvider,
)


class FakeKey:
    def __init__(self, value: bytes = b"k" * 32):
        self.value = value

    def get_or_create(self):
        return self.value


class Clock:
    def __init__(self):
        self.value = 1_700_000_000

    def __call__(self):
        return self.value


class Phase1CheckpointTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.clock = Clock()
        self.store = Phase1CheckpointStore(self.temp.name, key_provider=FakeKey(), clock=self.clock)
        self.snapshot = {
            "ready": True,
            "cookies": [{"name": "session", "value": "cookie-secret"}],
            "device_id": "device-secret",
            "sentinel_cache": {"token": "sentinel-secret"},
            "response": {"continue_url": "https://auth.example.test/add-phone?state=secret"},
            "continue_url": "https://auth.example.test/add-phone?state=secret",
        }

    def tearDown(self):
        self.temp.cleanup()

    def test_save_load_encrypts_payload_and_binds_identity(self):
        self.store.save(
            row_id="row-1",
            email="User@example.test",
            proxy="http://proxy.example:1",
            snapshot=self.snapshot,
            batch_id="batch-1",
            task_generation=2,
        )
        path = next(Path(self.temp.name).glob("*.json"))
        raw = path.read_text()
        self.assertNotIn("cookie-secret", raw)
        self.assertNotIn("sentinel-secret", raw)
        self.assertNotIn("state=secret", raw)
        loaded = self.store.load(
            row_id="row-1",
            email="user@example.test",
            proxy="http://proxy.example:1",
            task_generation=4,
        )
        self.assertEqual(loaded["snapshot"]["device_id"], "device-secret")
        self.assertEqual(loaded["public"]["state"], "restored")
        self.assertEqual((path.stat().st_mode & 0o777), 0o600)

        self.assertIsNone(
            self.store.load(
                row_id="row-1",
                email="other@example.test",
                proxy="http://proxy.example:1",
            )
        )

    def test_expiry_prunes_and_delete_is_safe(self):
        self.store.save(row_id="row-1", email="a@test.example", proxy="", snapshot=self.snapshot)
        self.clock.value += 1801
        self.assertIsNone(self.store.load(row_id="row-1", email="a@test.example", proxy=""))
        self.assertEqual(self.store.prune(), 0)
        self.store.delete("row-1")

    def test_disabled_store_never_falls_back_to_plaintext(self):
        store = Phase1CheckpointStore(
            self.temp.name,
            key_provider=FakeKey(b"short"),
        )
        with self.assertRaises(CheckpointDisabled):
            store.save(row_id="row", email="a@test.example", proxy="", snapshot=self.snapshot)
        self.assertFalse(store.enabled)

    def test_security_key_is_prompted_twice_from_stdin_not_argv(self):
        calls = []

        def runner(argv, **kwargs):
            calls.append((list(argv), kwargs))
            if "find-generic-password" in argv:
                return SimpleNamespace(returncode=44, stdout="")
            return SimpleNamespace(returncode=0, stdout="")

        SecurityKeyProvider(runner=runner).get_or_create()

        add_argv, add_kwargs = calls[1]
        self.assertEqual(add_argv[-1], "-w")
        prompt_values = add_kwargs["input"].splitlines()
        self.assertEqual(len(prompt_values), 2)
        self.assertEqual(prompt_values[0], prompt_values[1])
        self.assertNotIn(prompt_values[0], add_argv)

    def test_stop_event_is_checked_before_keychain_runner(self):
        calls = []
        stop = threading.Event()
        stop.set()

        def runner(argv, **kwargs):
            calls.append((argv, kwargs))
            return SimpleNamespace(returncode=44, stdout="")

        with self.assertRaisesRegex(CheckpointDisabled, "停止"):
            SecurityKeyProvider(runner=runner).get_or_create(stop_event=stop)
        self.assertEqual(calls, [])

    def test_stopping_one_attempt_does_not_disable_next_batch_checkpoint(self):
        class StopThenKey:
            def __init__(self):
                self.calls = 0

            def get_or_create(self, **_kwargs):
                self.calls += 1
                if self.calls == 1:
                    raise KeychainOperationStopped("任务已停止")
                return b"r" * 32

        provider = StopThenKey()
        store = Phase1CheckpointStore(self.temp.name, key_provider=provider)
        with self.assertRaises(CheckpointDisabled):
            store.save(
                row_id="row",
                email="a@test.example",
                proxy="",
                snapshot=self.snapshot,
                stop_event=lambda: True,
            )
        store.save(
            row_id="row",
            email="a@test.example",
            proxy="",
            snapshot=self.snapshot,
            stop_event=lambda: False,
        )
        self.assertEqual(provider.calls, 2)
        self.assertTrue(store.enabled)

    def test_runner_timeout_is_translated_to_keychain_unavailable(self):
        calls = []

        def runner(argv, **kwargs):
            calls.append((list(argv), kwargs))
            if "find-generic-password" in argv:
                return SimpleNamespace(returncode=44, stdout="")
            raise subprocess.TimeoutExpired(argv, kwargs.get("timeout", 0))

        with self.assertRaisesRegex(CheckpointDisabled, "超时"):
            SecurityKeyProvider(runner=runner, timeout_seconds=0.2).get_or_create()
        self.assertEqual(len(calls), 2)
        self.assertNotIn("input", calls[0][1])
        self.assertEqual(calls[1][1]["timeout"], 0.2)

    def test_legacy_runner_without_timeout_keyword_remains_compatible(self):
        calls = []

        def runner(argv, capture_output, text, check, input=None):
            calls.append((list(argv), input))
            if "find-generic-password" in argv:
                return SimpleNamespace(returncode=44, stdout="")
            return SimpleNamespace(returncode=0, stdout="")

        SecurityKeyProvider(runner=runner, timeout_seconds=0.2).get_or_create()
        self.assertEqual(len(calls), 2)
        self.assertEqual(len(calls[1][1].splitlines()), 2)

    def test_default_helper_is_terminated_when_stop_is_requested(self):
        stop = threading.Event()

        class HangingProcess:
            def __init__(self):
                self.stdin = None
                self.returncode = None
                self.terminated = False
                self.killed = False

            def poll(self):
                return self.returncode

            def communicate(self, timeout=None):
                raise subprocess.TimeoutExpired("security", timeout)

            def terminate(self):
                self.terminated = True
                self.returncode = -15

            def kill(self):
                self.killed = True
                self.returncode = -9

            def wait(self, timeout=None):
                return self.returncode

        process = HangingProcess()

        def popen(_argv, **_kwargs):
            stop.set()
            return process

        with patch("mac_overrides.keychain_runtime.subprocess.Popen", popen):
            with self.assertRaisesRegex(CheckpointDisabled, "停止"):
                SecurityKeyProvider(timeout_seconds=0.2).get_or_create(stop_event=stop)
        self.assertTrue(process.terminated or process.killed)

    def test_prompted_helper_uses_controlling_tty_and_reaps_success(self):
        # This mirrors the macOS security CLI contract: a bare ``-w`` reads
        # from /dev/tty, not the child's ordinary stdin pipe.
        code = (
            "handle = open('/dev/tty', 'r'); "
            "value = handle.readline().strip(); "
            "print('ok' if value == 'secret' else 'bad')"
        )
        result = SecurityKeyProvider(timeout_seconds=2)._run_default_subprocess(
            [sys.executable, "-c", code],
            input_text="secret\nsecret\n",
            stop_event=None,
            timeout_seconds=2,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("ok", result.stdout)

    def test_keychain_runner_failure_disables_encrypted_store(self):
        def unavailable(*_args, **_kwargs):
            raise OSError("security command unavailable")

        store = Phase1CheckpointStore(
            self.temp.name,
            key_provider=SecurityKeyProvider(runner=unavailable),
        )

        with self.assertRaises(CheckpointDisabled):
            store.save(row_id="row", email="a@test.example", proxy="", snapshot=self.snapshot)

        self.assertFalse(store.enabled)
        self.assertEqual(list(Path(self.temp.name).glob("*.json")), [])

    def test_untranslated_keychain_exception_disables_store_once(self):
        calls = []

        class BrokenKey:
            def get_or_create(self):
                calls.append(1)
                raise RuntimeError("security helper crashed")

        store = Phase1CheckpointStore(self.temp.name, key_provider=BrokenKey())
        with self.assertRaises(CheckpointDisabled):
            store.save(row_id="row", email="a@test.example", proxy="", snapshot=self.snapshot)
        with self.assertRaises(CheckpointDisabled):
            store.save(row_id="row", email="a@test.example", proxy="", snapshot=self.snapshot)
        self.assertFalse(store.enabled)
        self.assertEqual(len(calls), 1)

    def test_claim_rejects_another_task_but_allows_same_task_retry(self):
        self.store.save(row_id="row-1", email="a@test.example", proxy="", snapshot=self.snapshot)

        first = self.store.load(
            row_id="row-1",
            email="a@test.example",
            proxy="",
            task_generation=1,
            claim_id="task-one",
        )
        rejected = self.store.load(
            row_id="row-1",
            email="a@test.example",
            proxy="",
            task_generation=1,
            claim_id="task-two",
        )
        retry = self.store.load(
            row_id="row-1",
            email="a@test.example",
            proxy="",
            task_generation=2,
            claim_id="task-one",
        )

        self.assertIsNotNone(first)
        self.assertIsNone(rejected)
        self.assertIsNotNone(retry)

    def test_new_process_can_reclaim_an_interrupted_checkpoint_atomically(self):
        self.store.save(row_id="row-1", email="a@test.example", proxy="", snapshot=self.snapshot)
        first = self.store.load(
            row_id="row-1",
            email="a@test.example",
            proxy="",
            task_generation=1,
            claim_id="task-one",
        )
        self.assertIsNotNone(first)

        restarted = Phase1CheckpointStore(
            self.temp.name,
            key_provider=FakeKey(),
            clock=self.clock,
        )
        claimed = restarted.load(
            row_id="row-1",
            email="a@test.example",
            proxy="",
            task_generation=1,
            claim_id="task-two",
        )
        self.assertIsNotNone(claimed)

        self.assertIsNone(
            self.store.load(
                row_id="row-1",
                email="a@test.example",
                proxy="",
                task_generation=1,
                claim_id="task-three",
            )
        )

    def test_released_claim_can_be_reclaimed_by_new_task_in_same_process(self):
        self.store.save(row_id="row-1", email="a@test.example", proxy="", snapshot=self.snapshot)
        self.assertIsNotNone(
            self.store.load(
                row_id="row-1",
                email="a@test.example",
                proxy="",
                task_generation=1,
                claim_id="task-one",
            )
        )

        self.assertTrue(self.store.release("row-1", claim_id="task-one"))
        reclaimed = self.store.load(
            row_id="row-1",
            email="a@test.example",
            proxy="",
            task_generation=2,
            claim_id="task-two",
        )

        self.assertIsNotNone(reclaimed)

    def test_stale_process_cannot_release_another_process_claim(self):
        self.store.save(row_id="row-1", email="a@test.example", proxy="", snapshot=self.snapshot)
        self.assertIsNotNone(
            self.store.load(
                row_id="row-1",
                email="a@test.example",
                proxy="",
                claim_id="task-one",
            )
        )
        restarted = Phase1CheckpointStore(
            self.temp.name,
            key_provider=FakeKey(),
            clock=self.clock,
        )
        self.assertIsNotNone(
            restarted.load(
                row_id="row-1",
                email="a@test.example",
                proxy="",
                claim_id="task-two",
            )
        )

        self.assertFalse(self.store.release("row-1", claim_id="task-one"))
        self.assertIsNotNone(
            restarted.load(
                row_id="row-1",
                email="a@test.example",
                proxy="",
                claim_id="task-two",
            )
        )

    def test_old_owner_cannot_overwrite_after_reclaim(self):
        self.store.save(row_id="row-1", email="a@test.example", proxy="", snapshot=self.snapshot)
        self.assertIsNotNone(
            self.store.load(
                row_id="row-1",
                email="a@test.example",
                proxy="",
                task_generation=1,
                claim_id="task-one",
            )
        )
        restarted = Phase1CheckpointStore(
            self.temp.name,
            key_provider=FakeKey(),
            clock=self.clock,
        )
        self.assertIsNotNone(
            restarted.load(
                row_id="row-1",
                email="a@test.example",
                proxy="",
                task_generation=2,
                claim_id="task-two",
            )
        )
        changed = dict(self.snapshot, device_id="stale-owner")
        with self.assertRaises(CheckpointLeaseLost):
            self.store.save(
                row_id="row-1",
                email="a@test.example",
                proxy="",
                snapshot=changed,
            )
        loaded = restarted.load(
            row_id="row-1",
            email="a@test.example",
            proxy="",
            task_generation=2,
            claim_id="task-two",
        )
        self.assertEqual(loaded["snapshot"]["device_id"], "device-secret")

    def test_malformed_metadata_and_non_object_files_are_removed(self):
        self.store.save(row_id="row-1", email="a@test.example", proxy="", snapshot=self.snapshot)
        path = next(Path(self.temp.name).glob("*.json"))
        path.write_text(json.dumps({"meta": {"schema": "broken"}}), encoding="utf-8")
        self.assertIsNone(
            self.store.load(row_id="row-1", email="a@test.example", proxy="")
        )
        self.assertFalse(path.exists())

        path.write_text("[]", encoding="utf-8")
        self.assertEqual(self.store.prune(), 1)
        self.assertFalse(path.exists())


if __name__ == "__main__":
    unittest.main()
