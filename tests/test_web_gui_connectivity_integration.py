from __future__ import annotations

import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

from tests.web_gui_test_runtime import RecoveredWebGuiImport


PRIVATE_PROXY = "http://private-user:private-password@127.0.0.1:7897"


class FakeClock:
    def __init__(self, value: float = 1_000.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


class WebGuiConnectivityIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tempdir = tempfile.TemporaryDirectory()
        cls.previous_data_dir = os.environ.get("GPTPHONE_DATA_DIR")
        os.environ["GPTPHONE_DATA_DIR"] = cls.tempdir.name
        cls.web_gui_import = RecoveredWebGuiImport(Path(__file__).resolve().parents[1])
        cls.module = cls.web_gui_import.load()

    @classmethod
    def tearDownClass(cls):
        if cls.previous_data_dir is None:
            os.environ.pop("GPTPHONE_DATA_DIR", None)
        else:
            os.environ["GPTPHONE_DATA_DIR"] = cls.previous_data_dir
        cls.web_gui_import.cleanup()
        cls.tempdir.cleanup()

    def setUp(self):
        module = self.module
        self.originals = {
            "gate": module._PROTOCOL_GATE,
            "connectivity": module._OPENAI_CONNECTIVITY,
            "inflight": module._CURRENT_INFLIGHT_GATE,
            "proxy": module._CONNECTIVITY_PROXY,
            "batch_id": module._CONNECTIVITY_BATCH_ID,
            "notification_contexts": module._CONNECTIVITY_NOTIFICATION_CONTEXTS,
            "email": module._submit_connectivity_email,
            "stall": module._set_stall_notifications_suspended,
            "run": module._ORIGINAL_RUN_CODEX_AFTER_REGISTRATION,
            "emit": module._ORIGINAL_CHAIN_EMIT,
        }
        self.clock = FakeClock()
        self.notifications = []
        self.stall_states = []
        self.event_number = 0

        gate = module._sms_runtime_ext.ProxyProtocolGate(
            default_limit=8,
            now_fn=self.clock,
            launch_interval_seconds=0,
        )
        gate.begin_run(8, healthy_ceiling=12)
        inflight = module._performance_runtime_ext.InflightAdmissionGate(
            8,
            limit=20,
            enabled=True,
        )

        def event_id():
            self.event_number += 1
            return f"event{self.event_number}"

        module._PROTOCOL_GATE = gate
        module._CURRENT_INFLIGHT_GATE = inflight
        module._CONNECTIVITY_PROXY = PRIVATE_PROXY
        module._CONNECTIVITY_BATCH_ID = "batch-connectivity-test"
        module._CONNECTIVITY_NOTIFICATION_CONTEXTS = (
            module._connectivity_notifications_ext.ConnectivityIncidentContextStore()
        )
        module._submit_connectivity_email = self.notifications.append
        module._set_stall_notifications_suspended = self.stall_states.append
        module._ORIGINAL_CHAIN_EMIT = lambda *_args, **_kwargs: None
        module._OPENAI_CONNECTIVITY = (
            module._auth_connectivity_runtime_ext.OpenAIAuthConnectivityRuntime(
                proxy=PRIVATE_PROXY,
                now_fn=self.clock,
                probe_fn=lambda _origin, _proxy, _timeout: 204,
                auto_start_worker=False,
                id_factory=event_id,
                on_outage=module._on_connectivity_outage,
                on_recovery=module._on_connectivity_recovery,
            )
        )
        module._TASK_PROGRESS.reset()

    def tearDown(self):
        module = self.module
        module._OPENAI_CONNECTIVITY.close()
        module._TASK_PROGRESS.reset()
        module._PROTOCOL_GATE = self.originals["gate"]
        module._OPENAI_CONNECTIVITY = self.originals["connectivity"]
        module._CURRENT_INFLIGHT_GATE = self.originals["inflight"]
        module._CONNECTIVITY_PROXY = self.originals["proxy"]
        module._CONNECTIVITY_BATCH_ID = self.originals["batch_id"]
        module._CONNECTIVITY_NOTIFICATION_CONTEXTS = self.originals[
            "notification_contexts"
        ]
        module._submit_connectivity_email = self.originals["email"]
        module._set_stall_notifications_suspended = self.originals["stall"]
        module._ORIGINAL_RUN_CODEX_AFTER_REGISTRATION = self.originals["run"]
        module._ORIGINAL_CHAIN_EMIT = self.originals["emit"]

    def _run_auth_failures(self, failures):
        module = self.module
        outcomes = iter(failures)

        def fail(**_kwargs):
            raise next(outcomes)

        module._ORIGINAL_RUN_CODEX_AFTER_REGISTRATION = fail
        for index in range(len(failures)):
            task_id = f"T-auth-connectivity-{index}"
            module._TASK_PROGRESS.set_stage(task_id, "oauth_authorize_node")
            with self.assertRaises(RuntimeError):
                module._run_codex_after_registration(
                    oauth_url="https://auth.openai.com/authorize",
                    account_email="masked@example.test",
                    proxy=PRIVATE_PROXY,
                    config={"sms_task_id": task_id},
                )

    def _recover(self):
        self.clock.advance(10)
        first = self.module._OPENAI_CONNECTIVITY.run_probe_round()
        self.clock.advance(10)
        second = self.module._OPENAI_CONNECTIVITY.run_probe_round()
        self.assertFalse(first["recovered"])
        self.assertTrue(second["recovered"])

    def test_recovered_flask_app_installs_connectivity_guard_route(self):
        app = self.module._module.app
        rules = [
            rule
            for rule in app.url_map.iter_rules()
            if rule.rule == "/api/openai-connectivity-guard"
        ]

        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0].endpoint, "api_openai_connectivity_guard")
        self.assertIn("POST", rules[0].methods)
        self.assertNotIn("GET", rules[0].methods)
        self.assertTrue(callable(app.view_functions[rules[0].endpoint]))

    def test_batch_applies_current_outage_instead_of_begin_run_snapshot(self):
        module = self.module
        previous_connectivity = module._OPENAI_CONNECTIVITY
        original_start = module._importer_scheduler_ext.start_bounded_importer
        original_notifications = module._begin_notification_run
        observed = {}

        class Connectivity:
            def __init__(self):
                self._callback_lock = module.threading.RLock()
                self.condition = module.threading.Condition(module.threading.RLock())
                self.during_begin = None

            def begin_run(self, **kwargs):
                self.during_begin = (
                    module._CONNECTIVITY_PROXY,
                    module._CONNECTIVITY_BATCH_ID,
                    kwargs.get("proxy"),
                )
                return {"status": "healthy", "paused": False}

            def snapshot(self):
                return {
                    "status": "outage",
                    "enabled": True,
                    "paused": True,
                    "proxy_fingerprint": "sha256:test-only",
                    "event_id": "event-current",
                }

        next_proxy = "http://127.0.0.1:7898"

        def start(_importer, _settings, **kwargs):
            observed["protocol"] = module._PROTOCOL_GATE.snapshot(next_proxy)
            observed["inflight"] = kwargs["inflight_gate"].snapshot()
            return "started"

        connectivity = Connectivity()
        module._OPENAI_CONNECTIVITY = connectivity
        module._begin_notification_run = lambda *_args: None
        module._importer_scheduler_ext.start_bounded_importer = start
        importer = SimpleNamespace(status=lambda _settings: {"running": False})
        try:
            result = module._patched_importer_start(
                importer,
                {
                    "concurrency": 8,
                    "proxy": next_proxy,
                    "batch_id": "batch-next",
                },
            )
        finally:
            module._OPENAI_CONNECTIVITY = previous_connectivity
            module._begin_notification_run = original_notifications
            module._importer_scheduler_ext.start_bounded_importer = original_start

        self.assertEqual(result, "started")
        self.assertTrue(observed["protocol"]["paused"])
        self.assertTrue(observed["inflight"]["suspended"])
        self.assertEqual(self.stall_states, [True])
        self.assertEqual(
            connectivity.during_begin,
            (PRIVATE_PROXY, "batch-connectivity-test", next_proxy),
        )

    def test_batch_waits_for_callback_barrier_before_switching_gate_identity(self):
        module = self.module
        previous_connectivity = module._OPENAI_CONNECTIVITY
        original_start = module._importer_scheduler_ext.start_bounded_importer
        original_notifications = module._begin_notification_run
        entered = module.threading.Event()
        release = module.threading.Event()
        errors = []

        class BarrierLock:
            def __enter__(self):
                entered.set()
                if not release.wait(1):
                    raise RuntimeError("test callback barrier timed out")
                return self

            def __exit__(self, *_args):
                return None

        class Connectivity:
            _callback_lock = BarrierLock()
            condition = module.threading.Condition(module.threading.RLock())

            @staticmethod
            def begin_run(**_kwargs):
                return {"status": "healthy", "paused": False}

            @staticmethod
            def snapshot():
                return {"status": "healthy", "paused": False}

        module._OPENAI_CONNECTIVITY = Connectivity()
        module._begin_notification_run = lambda *_args: None
        module._importer_scheduler_ext.start_bounded_importer = (
            lambda *_args, **_kwargs: "started"
        )
        importer = SimpleNamespace(status=lambda _settings: {"running": False})

        def start_batch():
            try:
                module._patched_importer_start(
                    importer,
                    {
                        "concurrency": 5,
                        "proxy": "http://127.0.0.1:7898",
                        "batch_id": "batch-next",
                    },
                )
            except Exception as exc:
                errors.append(exc)

        worker = module.threading.Thread(target=start_batch)
        try:
            worker.start()
            self.assertTrue(entered.wait(1))
            self.assertEqual(
                module._PROTOCOL_GATE.snapshot(PRIVATE_PROXY)["baseline"],
                8,
            )
            self.assertEqual(module._CONNECTIVITY_PROXY, PRIVATE_PROXY)
            self.assertEqual(module._CONNECTIVITY_BATCH_ID, "batch-connectivity-test")
            release.set()
            worker.join(1)
        finally:
            release.set()
            worker.join(1)
            module._OPENAI_CONNECTIVITY = previous_connectivity
            module._begin_notification_run = original_notifications
            module._importer_scheduler_ext.start_bounded_importer = original_start

        self.assertFalse(worker.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(module._CONNECTIVITY_PROXY, "http://127.0.0.1:7898")
        self.assertEqual(module._CONNECTIVITY_BATCH_ID, "batch-next")

    def test_auth_two_network_failures_pause_at_baseline_and_notify_once(self):
        module = self.module
        self._run_auth_failures(
            [
                RuntimeError("SSLError: TLS handshake failed"),
                RuntimeError("curl: (56) remote disconnected"),
            ]
        )

        connectivity = module._OPENAI_CONNECTIVITY.snapshot()
        capacity = module._PROTOCOL_GATE.snapshot(PRIVATE_PROXY)
        inflight = module._CURRENT_INFLIGHT_GATE.snapshot()

        self.assertEqual(connectivity["status"], "outage")
        self.assertEqual(connectivity["affected_origins"], ["auth.openai.com"])
        self.assertTrue(capacity["paused"])
        self.assertEqual((capacity["baseline"], capacity["limit"]), (8, 8))
        self.assertTrue(inflight["suspended"])
        self.assertFalse(inflight["rolled_back"])
        self.assertEqual([row["kind"] for row in self.notifications], ["outage"])
        self.assertEqual(self.stall_states, [True])
        public_text = str((connectivity, capacity, self.notifications))
        self.assertNotIn("private-user", public_text)
        self.assertNotIn("private-password", public_text)

    def test_recovery_email_keeps_the_matching_outage_batch_identity(self):
        module = self.module
        previous_submit = module._submit_connectivity_email
        previous_service = module._CONNECTIVITY_EMAILS
        emails = []
        module._submit_connectivity_email = self.originals["email"]
        module._CONNECTIVITY_EMAILS = SimpleNamespace(
            submit=lambda notification: emails.append(notification) or True
        )
        try:
            self._run_auth_failures([
                RuntimeError("SSLError: TLS handshake failed"),
                RuntimeError("curl: (56) remote disconnected"),
            ])
            module._CONNECTIVITY_BATCH_ID = "batch-new"
            self._recover()
        finally:
            module._submit_connectivity_email = previous_submit
            module._CONNECTIVITY_EMAILS = previous_service

        self.assertEqual([item.kind for item in emails], ["outage", "recovery"])
        self.assertEqual(
            [item.batch_id for item in emails],
            ["batch-connectivity-test", "batch-connectivity-test"],
        )
        self.assertEqual(
            [
                (item.baseline, item.protocol_limit, item.healthy_ceiling)
                for item in emails
            ],
            [(8, 8, 12), (8, 8, 12)],
        )

    def test_recovery_email_after_restart_does_not_claim_the_new_batch(self):
        module = self.module
        previous_submit = module._submit_connectivity_email
        previous_service = module._CONNECTIVITY_EMAILS
        emails = []
        module._submit_connectivity_email = self.originals["email"]
        module._CONNECTIVITY_EMAILS = SimpleNamespace(
            submit=lambda notification: emails.append(notification) or True
        )
        try:
            self._run_auth_failures([
                RuntimeError("SSLError: TLS handshake failed"),
                RuntimeError("curl: (56) remote disconnected"),
            ])
            module._CONNECTIVITY_NOTIFICATION_CONTEXTS = (
                module._connectivity_notifications_ext.ConnectivityIncidentContextStore()
            )
            module._CONNECTIVITY_BATCH_ID = "batch-after-restart"
            self._recover()
        finally:
            module._submit_connectivity_email = previous_submit
            module._CONNECTIVITY_EMAILS = previous_service

        self.assertEqual([item.kind for item in emails], ["outage", "recovery"])
        self.assertEqual(emails[0].batch_id, "batch-connectivity-test")
        self.assertEqual(emails[1].batch_id, "")

    def test_sentinel_two_proxy_failures_use_the_same_recoverable_guard(self):
        module = self.module
        task_token = module._TASK_CONTEXT.set("T-sentinel-connectivity")
        try:
            for _index in range(2):
                module._patched_chain_emit(
                    None,
                    "[SentinelRunner] token 生成失败，重试 flow=chat-requirements: "
                    "ProxyError: unable to connect to proxy",
                    "warn",
                )
        finally:
            module._TASK_CONTEXT.reset(task_token)

        connectivity = module._OPENAI_CONNECTIVITY.snapshot()
        capacity = module._PROTOCOL_GATE.snapshot(PRIVATE_PROXY)
        self.assertEqual(connectivity["status"], "outage")
        self.assertEqual(connectivity["affected_origins"], ["sentinel.openai.com"])
        self.assertTrue(capacity["paused"])
        self.assertEqual(capacity["limit"], 8)
        self.assertEqual([row["kind"] for row in self.notifications], ["outage"])

    def test_429_and_non_openai_failures_never_create_connectivity_outage(self):
        module = self.module
        cases = (
            ("email_login", "mailbox_request_failed: TLS connection closed"),
            ("sms_waiting", "sms_provider_poll_failed: TLS connection closed"),
            ("oauth_authorize_node", "account_banned: account has been banned"),
            ("email_password", "password_verify_failed: invalid password"),
        )
        for index, (stage, detail) in enumerate(cases):
            with self.subTest(stage=stage):
                task_id = f"T-non-connectivity-{index}"
                module._TASK_PROGRESS.set_stage(task_id, stage)
                module._ORIGINAL_RUN_CODEX_AFTER_REGISTRATION = (
                    lambda error=detail, **_kwargs: (_ for _ in ()).throw(RuntimeError(error))
                )
                with self.assertRaises(RuntimeError):
                    module._run_codex_after_registration(
                        oauth_url="https://auth.openai.com/authorize",
                        account_email="masked@example.test",
                        proxy=PRIVATE_PROXY,
                        config={"sms_task_id": task_id},
                    )
                self.assertFalse(module._OPENAI_CONNECTIVITY.snapshot()["paused"])

        module._PROTOCOL_COORDINATOR.observe_connectivity_result(
            "auth.openai.com",
            {"status_code": 429},
            task_id="T-openai-429",
            proxy=PRIVATE_PROXY,
        )
        connectivity = module._OPENAI_CONNECTIVITY.snapshot()
        capacity = module._PROTOCOL_GATE.snapshot(PRIVATE_PROXY)
        self.assertFalse(connectivity["paused"])
        self.assertEqual(self.notifications, [])
        self.assertEqual((capacity["baseline"], capacity["limit"]), (8, 8))
        self.assertEqual(capacity["pause_reason"], "http_429")
        self.assertEqual(capacity["pause_remaining_seconds"], 30)
        self.assertTrue(capacity["sticky_baseline"])

    def test_oauth_session_invalidation_permanently_returns_inflight_to_baseline(self):
        module = self.module

        module._PROTOCOL_COORDINATOR.observe_main_chain_outcome(
            {"error": {"code": "oauth_session_invalid"}},
            succeeded=False,
            task_id="T-session-invalid",
            proxy=PRIVATE_PROXY,
            failure={"error_code": "oauth_session_invalid"},
        )

        inflight = module._CURRENT_INFLIGHT_GATE.snapshot()
        self.assertEqual(inflight["effective"], 8)
        self.assertTrue(inflight["rolled_back"])
        self.assertTrue(inflight["sticky_baseline"])
        self.assertEqual(inflight["reason"], "session_invalidation")

    def test_probe_recovery_needs_six_real_successes_and_second_outage_is_sticky(self):
        module = self.module
        coordinator = module._PROTOCOL_COORDINATOR
        failures = (
            RuntimeError("SSLError: TLS handshake failed"),
            RuntimeError("curl: (56) remote disconnected"),
        )

        for failure in failures:
            coordinator.observe_connectivity_result(
                "auth.openai.com",
                failure,
                task_id="T-first-outage",
                proxy=PRIVATE_PROXY,
            )
        self._recover()
        recovered = module._PROTOCOL_GATE.snapshot(PRIVATE_PROXY)
        self.assertEqual((recovered["limit"], recovered["healthy_ceiling"]), (8, 12))
        self.assertTrue(module._CURRENT_INFLIGHT_GATE.snapshot()["suspended"])

        for _index in range(5):
            coordinator.observe_connectivity_result(
                "auth.openai.com", succeeded=True, proxy=PRIVATE_PROXY
            )
        self.assertEqual(module._PROTOCOL_GATE.snapshot(PRIVATE_PROXY)["limit"], 8)
        self.assertTrue(module._CURRENT_INFLIGHT_GATE.snapshot()["suspended"])
        coordinator.observe_connectivity_result(
            "auth.openai.com", succeeded=True, proxy=PRIVATE_PROXY
        )
        self.assertEqual(module._PROTOCOL_GATE.snapshot(PRIVATE_PROXY)["limit"], 9)
        self.assertTrue(module._CURRENT_INFLIGHT_GATE.snapshot()["optimized"])

        for failure in failures:
            coordinator.observe_connectivity_result(
                "auth.openai.com",
                failure,
                task_id="T-second-outage",
                proxy=PRIVATE_PROXY,
            )
        self._recover()

        capacity = module._PROTOCOL_GATE.snapshot(PRIVATE_PROXY)
        inflight = module._CURRENT_INFLIGHT_GATE.snapshot()
        self.assertEqual((capacity["baseline"], capacity["limit"]), (8, 8))
        self.assertFalse(capacity["paused"])
        self.assertTrue(capacity["sticky_baseline"])
        self.assertFalse(capacity["expansion_enabled"])
        self.assertEqual(inflight["effective"], 8)
        self.assertTrue(inflight["rolled_back"])
        self.assertTrue(inflight["sticky_baseline"])
        self.assertEqual(
            [row["kind"] for row in self.notifications],
            ["outage", "recovery", "outage", "recovery"],
        )

    def test_six_healthy_responses_resume_inflight_when_protocol_ceiling_is_eight(self):
        module = self.module
        module._PROTOCOL_GATE.begin_run(8, healthy_ceiling=8)
        for failure in (
            RuntimeError("SSLError: TLS handshake failed"),
            RuntimeError("curl: (56) remote disconnected"),
        ):
            module._PROTOCOL_COORDINATOR.observe_connectivity_result(
                "auth.openai.com",
                failure,
                task_id="T-ceiling-eight",
                proxy=PRIVATE_PROXY,
            )
        self._recover()

        for _index in range(6):
            module._PROTOCOL_COORDINATOR.observe_connectivity_result(
                "auth.openai.com",
                succeeded=True,
                proxy=PRIVATE_PROXY,
            )

        capacity = module._PROTOCOL_GATE.snapshot(PRIVATE_PROXY)
        inflight = module._CURRENT_INFLIGHT_GATE.snapshot()
        self.assertEqual((capacity["baseline"], capacity["limit"]), (8, 8))
        self.assertFalse(inflight["suspended"])
        self.assertTrue(inflight["optimized"])
        self.assertEqual(inflight["effective"], 20)

    def test_disabling_guard_releases_connectivity_pause_immediately(self):
        module = self.module
        for failure in (
            RuntimeError("SSLError: TLS handshake failed"),
            RuntimeError("curl: (56) remote disconnected"),
        ):
            module._PROTOCOL_COORDINATOR.observe_connectivity_result(
                "auth.openai.com",
                failure,
                task_id="T-disable-guard",
                proxy=PRIVATE_PROXY,
            )

        self.assertTrue(module._OPENAI_CONNECTIVITY.snapshot()["paused"])
        self.assertTrue(module._PROTOCOL_GATE.snapshot(PRIVATE_PROXY)["paused"])
        self.assertTrue(module._CURRENT_INFLIGHT_GATE.snapshot()["suspended"])

        module._write_local_config({
            "openai_connectivity_guard": False,
            "proxy": PRIVATE_PROXY,
        })

        connectivity = module._OPENAI_CONNECTIVITY.snapshot()
        capacity = module._PROTOCOL_GATE.snapshot(PRIVATE_PROXY)
        inflight = module._CURRENT_INFLIGHT_GATE.snapshot()
        self.assertFalse(connectivity["enabled"])
        self.assertFalse(connectivity["paused"])
        self.assertFalse(capacity["paused"])
        self.assertEqual(capacity["limit"], 8)
        self.assertFalse(inflight["suspended"])
        self.assertTrue(inflight["optimized"])
        self.assertEqual(self.stall_states, [True, False])

    def test_stop_sets_the_event_before_waking_protocol_waiters(self):
        module = self.module
        original_stop = module._importer_scheduler_ext.stop_bounded_importer
        original_context = module._notification_context_for
        observed = []

        class StopEvent:
            stopped = False

            def set(self):
                self.stopped = True
                observed.append("set")

        stop_event = StopEvent()

        class Gate:
            def wake_all(self):
                self.assert_stopped()
                observed.append("protocol_wake")

            @staticmethod
            def assert_stopped():
                if not stop_event.stopped:
                    raise AssertionError("protocol waiters woke before stop_event")

        class Connectivity:
            def wake_waiters(self):
                Gate.assert_stopped()
                observed.append("connectivity_wake")

        previous_gate = module._PROTOCOL_GATE
        previous_connectivity = module._OPENAI_CONNECTIVITY
        module._PROTOCOL_GATE = Gate()
        module._OPENAI_CONNECTIVITY = Connectivity()
        module._notification_context_for = lambda *_args: None
        module._importer_scheduler_ext.stop_bounded_importer = (
            lambda _importer: observed.append("scheduler_stop")
        )
        try:
            module._patched_importer_stop(SimpleNamespace(stop_event=stop_event))
        finally:
            module._PROTOCOL_GATE = previous_gate
            module._OPENAI_CONNECTIVITY = previous_connectivity
            module._notification_context_for = original_context
            module._importer_scheduler_ext.stop_bounded_importer = original_stop

        self.assertEqual(
            observed,
            ["set", "connectivity_wake", "protocol_wake", "scheduler_stop"],
        )

    def test_phone_submit_and_sentinel_refresh_each_take_a_short_protocol_lease(self):
        module = self.module
        leases = []
        base_gate = module._PROTOCOL_GATE

        class Lease:
            def __init__(self, inner):
                self.inner = inner

            def __enter__(self):
                leases.append("acquired")
                return self.inner.__enter__()

            def __exit__(self, *args):
                return self.inner.__exit__(*args)

        class CountingGate:
            def acquire(self, proxy, **kwargs):
                return Lease(base_gate.acquire(proxy, **kwargs))

            def report(self, *args, **kwargs):
                return base_gate.report(*args, **kwargs)

            def snapshot(self, proxy):
                return base_gate.snapshot(proxy)

            def guard_expansion(self, proxy):
                return base_gate.guard_expansion(proxy)

            def pause_connectivity(self, proxy):
                return base_gate.pause_connectivity(proxy)

        class Session:
            cookies = {"session": "present"}

            @staticmethod
            def post(_url, **_kwargs):
                return {"_status": 200, "page": {"type": "add_phone"}}

        class Sentinel:
            @staticmethod
            def reset(_flow=""):
                return None

            @staticmethod
            def token_for(_flow, _context):
                module._patched_chain_emit(
                    None,
                    "[SentinelRunner] token 生成成功, flow=chat-requirements, 包含 so=False",
                    "info",
                )
                return {"token": "safe-test-token"}

        transport = type("Transport", (), {})()
        transport.config = {
            "sms_task_id": "T-phone-short-leases",
            "_auth_account_email": "masked@example.test",
        }
        transport.account_email = "masked@example.test"
        transport.session = Session()
        transport.sentinel_provider = Sentinel()
        transport.device_id = "device-safe"
        transport.proxy = PRIVATE_PROXY
        transport._gptphone_page_type = "add_phone"
        module._PROTOCOL_GATE = CountingGate()
        module._AUTH_SESSIONS.clear("T-phone-short-leases")
        try:
            response = module._real_send_phone_number_otp(
                transport,
                "+15550001234",
                "sms",
            )
        finally:
            module._AUTH_SESSIONS.clear("T-phone-short-leases")

        self.assertEqual(response["_status"], 200)
        self.assertEqual(leases, ["acquired", "acquired"])
        for _index in range(3):
            module._PROTOCOL_COORDINATOR.observe_connectivity_result(
                "auth.openai.com", succeeded=True, proxy=PRIVATE_PROXY
            )
        self.assertEqual(base_gate.snapshot(PRIVATE_PROXY)["limit"], 8)
        module._PROTOCOL_COORDINATOR.observe_connectivity_result(
            "auth.openai.com", succeeded=True, proxy=PRIVATE_PROXY
        )
        self.assertEqual(base_gate.snapshot(PRIVATE_PROXY)["limit"], 9)


if __name__ == "__main__":
    unittest.main()
