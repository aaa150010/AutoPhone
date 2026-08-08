from __future__ import annotations

import os
import socket
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from mac_overrides import transport_lifecycle
from mac_overrides.transport_lifecycle import (
    TaskTransportRegistry,
    close_transport,
    is_fd_exhaustion,
    process_fd_ratio,
    process_resource_snapshot,
)


class FakeSession:
    def __init__(self) -> None:
        self.closed = 0

    def close(self) -> None:
        self.closed += 1


class FlakySession(FakeSession):
    def __init__(self, failures: int = 1) -> None:
        super().__init__()
        self.failures = failures

    def close(self) -> None:
        self.closed += 1
        if self.closed <= self.failures:
            raise OSError("temporary close failure")


class FakePipe:
    def __init__(self) -> None:
        self.closed = 0

    def close(self) -> None:
        self.closed += 1


class FakeNodeProcess:
    def __init__(self, *, args=None) -> None:
        self.args = args or ["node", "sentinel.js"]
        self.pid = None
        self.stdin = FakePipe()
        self.stdout = FakePipe()
        self.stderr = FakePipe()
        self.terminated = 0
        self.killed = 0
        self.waited = 0

    def poll(self):
        return None

    def terminate(self) -> None:
        self.terminated += 1

    def kill(self) -> None:
        self.killed += 1

    def wait(self, timeout=None) -> int:
        self.waited += 1
        return 0


def transport(task_id: str):
    return SimpleNamespace(config={"sms_task_id": task_id}, session=FakeSession())


class TaskTransportRegistryTests(unittest.TestCase):
    def test_replacing_transport_closes_displaced_session(self):
        registry = TaskTransportRegistry()
        first = transport("T001")
        second = transport("T001")

        registry.register("T001", first)
        registry.register("T001", second)

        self.assertEqual(first.session.closed, 1)
        self.assertIs(registry.get("T001"), second)
        self.assertEqual(registry.snapshot()["active_transports"], 1)

    def test_task_cleanup_unregisters_and_closes_exactly_once(self):
        registry = TaskTransportRegistry()
        value = transport("T001")
        registry.register("T001", value)

        self.assertTrue(registry.close_task("T001"))
        self.assertFalse(registry.close_task("T001"))
        self.assertEqual(value.session.closed, 1)
        self.assertIsNone(registry.get("T001"))

    def test_task_cleanup_retains_failed_resources_for_a_second_close(self):
        registry = TaskTransportRegistry()
        session = FlakySession()
        value = SimpleNamespace(
            config={"sms_task_id": "T001"},
            session=session,
        )
        registry.register("T001", value)

        self.assertFalse(registry.close_task("T001"))
        self.assertIsNone(registry.get("T001"))
        self.assertEqual(registry.snapshot()["pending_cleanup"], 1)
        self.assertEqual(registry.snapshot()["closed_transports"], 0)

        self.assertTrue(registry.close_task("T001"))
        self.assertEqual(registry.snapshot()["pending_cleanup"], 0)
        self.assertEqual(registry.snapshot()["closed_transports"], 1)
        self.assertEqual(session.closed, 2)

    def test_task_cleanup_reports_incomplete_when_only_some_resources_closed(self):
        registry = TaskTransportRegistry()
        session = FakeSession()
        auth_session = FlakySession()
        value = SimpleNamespace(
            config={"sms_task_id": "T001"},
            session=session,
            auth_session=auth_session,
        )
        registry.register("T001", value)

        self.assertFalse(registry.close_task("T001"))
        self.assertEqual(registry.snapshot()["pending_cleanup"], 1)
        self.assertTrue(registry.close_task("T001"))
        self.assertEqual(session.closed, 1)
        self.assertEqual(auth_session.closed, 2)

    def test_clear_retries_and_retains_still_failing_cleanup(self):
        registry = TaskTransportRegistry()
        session = FlakySession(failures=2)
        value = SimpleNamespace(
            config={"sms_task_id": "T001"},
            session=session,
        )
        registry.register("T001", value)

        self.assertFalse(registry.close_task("T001"))
        self.assertEqual(registry.clear(), 0)
        self.assertEqual(registry.snapshot()["pending_cleanup"], 1)

        self.assertEqual(registry.clear(), 1)
        self.assertEqual(registry.snapshot()["pending_cleanup"], 0)
        self.assertEqual(session.closed, 3)

    def test_displaced_transport_cleanup_failure_stays_retryable(self):
        registry = TaskTransportRegistry()
        first = SimpleNamespace(
            config={"sms_task_id": "T001"},
            session=FlakySession(),
        )
        second = transport("T001")

        registry.register("T001", first)
        registry.register("T001", second)

        self.assertIs(registry.get("T001"), second)
        self.assertEqual(registry.snapshot()["pending_cleanup"], 1)
        self.assertTrue(registry.close_task("T001"))
        self.assertEqual(registry.snapshot()["pending_cleanup"], 0)
        self.assertFalse(registry.close_task("T001"))
        self.assertEqual(first.session.closed, 2)
        self.assertEqual(second.session.closed, 1)

    def test_task_cleanup_attempts_active_and_all_pending_transports(self):
        registry = TaskTransportRegistry()
        first = SimpleNamespace(
            config={"sms_task_id": "T001"},
            session=FlakySession(failures=3),
        )
        second = SimpleNamespace(
            config={"sms_task_id": "T001"},
            session=FlakySession(failures=2),
        )
        active = transport("T001")

        registry.register("T001", first)
        registry.register("T001", second)
        registry.register("T001", active)

        self.assertEqual(registry.snapshot()["pending_cleanup"], 2)
        self.assertFalse(registry.close_task("T001"))
        self.assertEqual(active.session.closed, 1)
        self.assertEqual(first.session.closed, 2)
        self.assertEqual(second.session.closed, 2)
        self.assertEqual(registry.snapshot()["active_transports"], 0)
        self.assertEqual(registry.snapshot()["pending_cleanup"], 2)

        self.assertFalse(registry.close_task("T001"))
        self.assertEqual(registry.snapshot()["pending_cleanup"], 1)
        self.assertTrue(registry.close_task("T001"))
        self.assertEqual(registry.snapshot()["pending_cleanup"], 0)

    def test_task_cleanup_does_not_report_success_when_cleanup_registers_more(self):
        first = transport("T001")
        displaced = transport("T001")
        late_active = transport("T001")
        registry = None
        retry_allowed = False

        def close_with_late_registration(value):
            if value is first:
                registry.register("T001", displaced)
                registry.register("T001", late_active)
            if value is displaced and not retry_allowed:
                return False
            value.session.close()
            return True

        registry = TaskTransportRegistry(close_fn=close_with_late_registration)
        registry.register("T001", first)

        self.assertFalse(registry.close_task("T001"))
        self.assertIs(registry.get("T001"), late_active)
        self.assertEqual(registry.snapshot()["pending_cleanup"], 1)

        retry_allowed = True
        self.assertTrue(registry.close_task("T001"))
        self.assertEqual(registry.snapshot()["active_transports"], 0)
        self.assertEqual(registry.snapshot()["pending_cleanup"], 0)

    def test_stale_binding_is_dropped_without_returning_wrong_transport(self):
        registry = TaskTransportRegistry()
        value = transport("T002")
        registry.register("T001", value)

        self.assertIsNone(registry.get("T001"))
        self.assertEqual(registry.snapshot()["active_transports"], 0)

    def test_close_transport_tolerates_missing_session_and_is_idempotent(self):
        value = SimpleNamespace()
        self.assertFalse(close_transport(value))
        self.assertFalse(close_transport(value))

    def test_close_transport_closes_session_auth_session_and_owned_node(self):
        session = FakeSession()
        auth_session = FakeSession()
        process = FakeNodeProcess()
        value = SimpleNamespace(
            session=session,
            auth_session=auth_session,
            node_process=process,
        )

        self.assertTrue(close_transport(value))
        self.assertFalse(close_transport(value))
        self.assertEqual(session.closed, 1)
        self.assertEqual(auth_session.closed, 1)
        self.assertEqual(process.stdin.closed, 1)
        self.assertEqual(process.stdout.closed, 1)
        self.assertEqual(process.stderr.closed, 1)
        self.assertEqual(process.terminated, 1)
        self.assertEqual(process.waited, 1)
        self.assertEqual(process.killed, 0)

    def test_close_transport_retries_only_resources_that_failed(self):
        session = FakeSession()
        auth_session = FlakySession()
        value = SimpleNamespace(session=session, auth_session=auth_session)

        self.assertTrue(close_transport(value))
        self.assertFalse(getattr(value, "_gptphone_transport_closed", False))
        self.assertEqual(session.closed, 1)
        self.assertEqual(auth_session.closed, 1)

        self.assertTrue(close_transport(value))
        self.assertTrue(value._gptphone_transport_closed)
        self.assertEqual(session.closed, 1)
        self.assertEqual(auth_session.closed, 2)
        self.assertFalse(close_transport(value))

    def test_registered_owned_node_does_not_need_ps_during_emfile_cleanup(self):
        registry = TaskTransportRegistry()
        process = FakeNodeProcess()
        process.pid = 4242
        value = SimpleNamespace(
            config={"sms_task_id": "T001"},
            node_process=process,
        )

        with patch.object(
            transport_lifecycle,
            "_direct_child_ppid",
            return_value=os.getpid(),
        ) as ppid:
            registry.register("T001", value)
            self.assertEqual(ppid.call_count, 1)
            ppid.side_effect = OSError(24, "Too many open files")
            self.assertTrue(registry.close_task("T001"))

        self.assertEqual(ppid.call_count, 1)
        self.assertEqual(process.terminated, 1)

    def test_unverified_explicit_node_process_is_never_stopped(self):
        registry = TaskTransportRegistry()
        process = FakeNodeProcess()
        process.pid = 4242
        value = SimpleNamespace(
            config={"sms_task_id": "T001"},
            node_process=process,
        )

        with patch.object(
            transport_lifecycle,
            "_direct_child_ppid",
            return_value=os.getpid() + 1,
        ):
            registry.register("T001", value)
            self.assertTrue(registry.close_task("T001"))

        self.assertEqual(process.terminated, 0)
        self.assertEqual(process.killed, 0)

    def test_unknown_node_ownership_keeps_cleanup_retryable(self):
        process = FakeNodeProcess()
        process.pid = 4242
        value = SimpleNamespace(node_process=process)

        with patch.object(
            transport_lifecycle,
            "_direct_child_ppid",
            side_effect=[None, os.getpid()],
        ):
            self.assertFalse(close_transport(value))
            self.assertFalse(getattr(value, "_gptphone_transport_closed", False))
            self.assertTrue(value._gptphone_transport_cleanup_pending)
            self.assertTrue(close_transport(value))

        self.assertTrue(value._gptphone_transport_closed)
        self.assertEqual(process.terminated, 1)

    def test_close_transport_does_not_stop_generic_non_node_process(self):
        process = FakeNodeProcess(args=["python3", "worker.py"])
        value = SimpleNamespace(session=FakeSession(), process=process)

        self.assertTrue(close_transport(value))
        self.assertEqual(process.terminated, 0)
        self.assertEqual(process.stdin.closed, 0)

    def test_fd_snapshot_and_exhaustion_classifier_are_safe(self):
        snapshot = process_resource_snapshot(now_fn=lambda: 123.0)
        self.assertEqual(snapshot.observed_at, 123.0)
        self.assertGreaterEqual(snapshot.open_fds or 0, 0)
        self.assertGreaterEqual(snapshot.pipe_fds or 0, 0)
        self.assertGreaterEqual(snapshot.socket_fds or 0, 0)
        self.assertGreaterEqual(snapshot.close_wait_sockets or 0, 0)
        self.assertGreaterEqual(snapshot.node_child_processes or 0, 0)
        self.assertTrue(is_fd_exhaustion("[Errno 24] Too many open files"))
        self.assertFalse(is_fd_exhaustion("TLS connection reset"))

    def test_lightweight_fd_ratio_never_spawns_diagnostic_processes(self):
        with (
            patch.object(transport_lifecycle, "_fd_directory", return_value=SimpleNamespace()),
            patch.object(
                transport_lifecycle,
                "_fd_counts",
                return_value=(65, 0, 0, set()),
            ),
            patch.object(
                transport_lifecycle.resource,
                "getrlimit",
                return_value=(100, 100),
            ),
            patch.object(
                transport_lifecycle.subprocess,
                "run",
                side_effect=AssertionError("periodic FD sampling must not spawn a process"),
            ) as run,
        ):
            self.assertEqual(process_fd_ratio(), 0.65)

        run.assert_not_called()

    def test_darwin_close_wait_parser_accepts_lsof_fd_mode_suffix(self):
        completed = SimpleNamespace(returncode=0, stdout="p123\nf12u\nf13u\nf12r\n")
        with patch.object(transport_lifecycle.subprocess, "run", return_value=completed):
            self.assertEqual(transport_lifecycle._darwin_close_wait_count(), 2)

    def test_fd_snapshot_classifies_current_process_pipe_and_socket(self):
        before = process_resource_snapshot()
        if before.open_fds is None or before.pipe_fds is None or before.socket_fds is None:
            self.skipTest("process FD classification is unavailable")
        read_fd, write_fd = os.pipe()
        left, right = socket.socketpair()
        try:
            during = process_resource_snapshot()
            self.assertGreaterEqual(during.open_fds or 0, before.open_fds + 4)
            self.assertGreaterEqual(during.pipe_fds or 0, before.pipe_fds + 2)
            self.assertGreaterEqual(during.socket_fds or 0, before.socket_fds + 2)
        finally:
            os.close(read_fd)
            os.close(write_fd)
            left.close()
            right.close()

    def test_120_fake_transport_lifecycles_return_to_fd_baseline(self):
        registry = TaskTransportRegistry()
        baseline = process_resource_snapshot().open_fds
        transports = []

        for offset in range(0, 120, 8):
            current = []
            for index in range(offset, offset + 8):
                read_fd, write_fd = os.pipe()
                read_file = os.fdopen(read_fd, "rb", closefd=True)
                write_file = os.fdopen(write_fd, "wb", closefd=True)
                session = FakeSession()
                value = SimpleNamespace(
                    config={"sms_task_id": f"T{index:03d}"},
                    session=session,
                    node_stdin=write_file,
                    node_stdout=read_file,
                )
                current.append(value)
                transports.append(value)
                registry.register(f"T{index:03d}", value)
            for index, value in enumerate(current, start=offset):
                self.assertTrue(registry.close_task(f"T{index:03d}"))
                self.assertFalse(registry.close_task(f"T{index:03d}"))

        final = process_resource_snapshot().open_fds
        self.assertEqual(registry.snapshot()["active_transports"], 0)
        self.assertEqual(registry.snapshot()["closed_transports"], 120)
        self.assertTrue(all(value.session.closed == 1 for value in transports))
        if baseline is not None and final is not None:
            self.assertLessEqual(abs(final - baseline), 5)


if __name__ == "__main__":
    unittest.main()
