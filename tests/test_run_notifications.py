from __future__ import annotations

import threading
import unittest

from mac_overrides.run_notifications import (
    DEFAULT_EVENT_SETTINGS,
    EVENT_BATCH_COMPLETED,
    EVENT_MANUAL_STOP,
    EVENT_OPENAI_AUTH_CONNECTIVITY,
    EVENT_SMS_BALANCE_LOW,
    EVENT_SMS_EXHAUSTED,
    EVENT_STALLED,
    EVENT_UNEXPECTED_STOP,
    NOTIFICATION_QUEUE_CAPACITY,
    NotificationConfigError,
    NotificationQueue,
    OpenAIConnectivityNotification,
    RunAggregate,
    RunNotification,
    RunNotificationCoordinator,
    RunNotificationService,
    SmsBalanceAlert,
    SmtpNotificationSender,
    build_notification_message,
    normalize_email_notification,
    normalize_recipients,
    send_test_notification,
    validate_email_notification,
)
from mac_overrides.connectivity_notifications import (
    ConnectivityIncidentContextStore,
    OpenAIConnectivityNotificationService,
)


def enabled_config(**values):
    config = {
        "enabled": True,
        "provider": "qq",
        "username": "notifier@qq.com",
        "password": "smtp-secret",
        "sender": "notifier@qq.com",
        "recipients": ["ops@example.test"],
    }
    config.update(values)
    return config


class FakeClock:
    def __init__(self, value: float = 0.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


class ConnectivityIncidentContextStoreTests(unittest.TestCase):
    @staticmethod
    def payload(
        kind="outage",
        event_id="incident123",
        fingerprint="sha256:0123456789abcdef",
    ):
        return {
            "kind": kind,
            "event_id": event_id,
            "reason_code": "openai_proxy_connection_failure",
            "affected_origins": ["auth.openai.com"],
            "proxy_fingerprint": fingerprint,
        }

    def test_recovery_reuses_only_the_matching_outage_batch_and_capacity(self):
        store = ConnectivityIncidentContextStore()
        outage = store.build_notification(
            self.payload(),
            batch_id="batch-original",
            capacity={"baseline": 8, "limit": 8, "healthy_ceiling": 12},
        )
        recovery = store.build_notification(
            self.payload(kind="recovery"),
            batch_id="batch-new",
            capacity={"baseline": 9, "limit": 9, "healthy_ceiling": 15},
        )

        self.assertEqual(outage.batch_id, "batch-original")
        self.assertEqual(recovery.batch_id, "batch-original")
        self.assertEqual(
            (recovery.baseline, recovery.protocol_limit, recovery.healthy_ceiling),
            (8, 8, 12),
        )

    def test_sticky_incident_reports_a_fixed_baseline_instead_of_false_ceiling(self):
        store = ConnectivityIncidentContextStore()
        outage = store.build_notification(
            self.payload(),
            batch_id="batch-sticky",
            capacity={
                "baseline": 8,
                "limit": 8,
                "healthy_ceiling": 12,
                "sticky_baseline": True,
            },
        )

        self.assertTrue(outage.sticky_baseline)
        self.assertEqual(outage.healthy_ceiling, 8)

    def test_recovery_without_process_context_never_uses_the_current_batch(self):
        restarted_store = ConnectivityIncidentContextStore()

        recovery = restarted_store.build_notification(
            self.payload(kind="recovery"),
            batch_id="batch-must-not-be-used",
            capacity={"baseline": 8, "limit": 8, "healthy_ceiling": 12},
        )

        self.assertEqual(recovery.batch_id, "")
        self.assertEqual(
            (recovery.baseline, recovery.protocol_limit, recovery.healthy_ceiling),
            (8, 8, 12),
        )

    def test_mismatched_recovery_does_not_reuse_another_incident(self):
        store = ConnectivityIncidentContextStore()
        store.build_notification(
            self.payload(event_id="incidentOld"),
            batch_id="batch-old",
            capacity={"baseline": 8, "limit": 8, "healthy_ceiling": 12},
        )

        recovery = store.build_notification(
            self.payload(kind="recovery", event_id="incidentNew"),
            batch_id="batch-new",
            capacity={"baseline": 9, "limit": 9, "healthy_ceiling": 15},
        )

        self.assertEqual(recovery.batch_id, "")
        self.assertEqual(recovery.baseline, 9)

    def test_recovery_with_same_event_but_different_proxy_does_not_match(self):
        store = ConnectivityIncidentContextStore()
        store.build_notification(
            self.payload(),
            batch_id="batch-old",
            capacity={"baseline": 8, "limit": 8, "healthy_ceiling": 12},
        )

        recovery = store.build_notification(
            self.payload(
                kind="recovery",
                fingerprint="sha256:fedcba9876543210",
            ),
            batch_id="batch-new",
            capacity={"baseline": 9, "limit": 9, "healthy_ceiling": 15},
        )

        self.assertEqual(recovery.batch_id, "")
        self.assertEqual(recovery.healthy_ceiling, 15)


class FakeSmtpClient:
    def __init__(self, host, port, *, timeout) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self.calls: list[object] = []
        self.messages: list[tuple] = []

    def __enter__(self):
        self.calls.append("enter")
        return self

    def __exit__(self, *_args):
        self.calls.append("exit")

    def ehlo(self):
        self.calls.append("ehlo")

    def starttls(self):
        self.calls.append("starttls")

    def login(self, username, password):
        self.calls.append(("login", username, password))

    def send_message(self, message, *, from_addr, to_addrs):
        self.calls.append("send_message")
        self.messages.append((message, from_addr, to_addrs))


class FakeSmtpFactory:
    def __init__(self) -> None:
        self.clients: list[FakeSmtpClient] = []

    def __call__(self, host, port, *, timeout):
        client = FakeSmtpClient(host, port, timeout=timeout)
        self.clients.append(client)
        return client


class ConfigTests(unittest.TestCase):
    def test_defaults_are_disabled_and_enable_expected_events(self):
        config = normalize_email_notification()

        self.assertFalse(config["enabled"])
        self.assertEqual(config["provider"], "qq")
        self.assertEqual(config["smtp_host"], "smtp.qq.com")
        self.assertEqual(config["smtp_port"], 465)
        self.assertEqual(config["security"], "ssl")
        self.assertEqual(config["stalled_minutes"], 10)
        self.assertEqual(config["events"], DEFAULT_EVENT_SETTINGS)
        self.assertFalse(config["events"][EVENT_MANUAL_STOP])

    def test_transport_is_always_qq_ssl_and_alias_fields_are_normalized(self):
        config = normalize_email_notification({
            "smtp_provider": " CUSTOM ",
            "smtp_host": " smtp.example.test ",
            "smtp_security": " STARTTLS ",
            "smtp_username": " sender@qq.com ",
            "smtp_password": " auth-code ",
            "recipient_emails": " a@example.test; B@example.test\nA@example.test ",
            "stalled_minutes": "15",
            "events": {EVENT_MANUAL_STOP: "yes", EVENT_STALLED: "false"},
        })

        self.assertEqual(config["provider"], "qq")
        self.assertEqual(config["smtp_host"], "smtp.qq.com")
        self.assertEqual(config["smtp_port"], 465)
        self.assertEqual(config["security"], "ssl")
        self.assertEqual(config["sender"], "sender@qq.com")
        self.assertEqual(
            config["recipients"],
            ["a@example.test", "B@example.test"],
        )
        self.assertEqual(config["stalled_minutes"], 15)
        self.assertTrue(config["events"][EVENT_MANUAL_STOP])
        self.assertFalse(config["events"][EVENT_STALLED])

    def test_recipient_lists_are_trimmed_split_and_deduplicated(self):
        self.assertEqual(
            normalize_recipients([
                " one@example.test, TWO@example.test ",
                "two@example.test",
                "",
                "three@example.test",
            ]),
            ["one@example.test", "TWO@example.test", "three@example.test"],
        )

    def test_enabled_configuration_validates_required_fields_without_values(self):
        secret = "must-not-appear"
        with self.assertRaises(NotificationConfigError) as raised:
            validate_email_notification({
                "enabled": True,
                "provider": "custom",
                "host": "",
                "port": "bad",
                "security": "plain",
                "username": "",
                "password": secret,
                "sender": "not-an-address",
                "recipients": [],
            })

        message = str(raised.exception)
        self.assertIn("username", message)
        self.assertIn("sender", message)
        self.assertIn("recipients", message)
        self.assertNotIn(secret, message)

    def test_disabled_configuration_can_be_saved_while_incomplete(self):
        config = validate_email_notification({
            "enabled": False,
            "provider": "custom",
            "host": "",
            "port": "bad",
            "security": "plain",
        })
        self.assertFalse(config["enabled"])
        self.assertEqual(config["provider"], "qq")
        self.assertEqual(config["smtp_port"], 465)
        self.assertEqual(config["security"], "ssl")

    def test_enabled_valid_configuration_is_canonical(self):
        config = validate_email_notification(enabled_config(
            recipients=[" ops@example.test ", "OPS@example.test"],
        ))
        self.assertEqual(config["recipients"], ["ops@example.test"])
        self.assertEqual(config["smtp_host"], "smtp.qq.com")


class TransportTests(unittest.TestCase):
    def test_ssl_sender_uses_timeout_and_aggregate_only_message(self):
        ssl_factory = FakeSmtpFactory()
        sender = SmtpNotificationSender(
            enabled_config(password="smtp-password-never-in-mail"),
            smtp_ssl_factory=ssl_factory,
        )
        sender.send(RunNotification(
            EVENT_BATCH_COMPLETED,
            RunAggregate(total=7, succeeded=4, failed=2, stopped=1),
        ))

        self.assertEqual(len(ssl_factory.clients), 1)
        client = ssl_factory.clients[0]
        self.assertEqual((client.host, client.port, client.timeout), ("smtp.qq.com", 465, 10))
        self.assertEqual(
            client.calls,
            [
                "enter",
                ("login", "notifier@qq.com", "smtp-password-never-in-mail"),
                "send_message",
                "exit",
            ],
        )
        message, from_addr, to_addrs = client.messages[0]
        body = message.get_content()
        self.assertIn("[GPT 注册中心][普通流程] 批次完成", message["Subject"])
        self.assertEqual(from_addr, "notifier@qq.com")
        self.assertEqual(to_addrs, ["ops@example.test"])
        self.assertIn("处理总数：7", body)
        self.assertIn("链路：普通流程", body)
        self.assertIn("成功：4", body)
        self.assertNotIn("smtp-password-never-in-mail", message.as_string())

    def test_connectivity_message_contains_only_stable_safe_metadata(self):
        ssl_factory = FakeSmtpFactory()
        sender = SmtpNotificationSender(
            enabled_config(password="smtp-secret-never-in-mail"),
            smtp_ssl_factory=ssl_factory,
        )
        sender.send_connectivity(OpenAIConnectivityNotification(
            kind="outage",
            event_id="incident123",
            batch_id="batch-safe",
            reason_code="openai_tls_connection_failure",
            affected_origins=("auth.openai.com",),
            detected_at=1_700_000_000,
            baseline=8,
            protocol_limit=8,
            healthy_ceiling=12,
            proxy_fingerprint="sha256:0123456789abcdef",
        ))

        message = ssl_factory.clients[0].messages[0][0]
        rendered = message.as_string()
        body = message.get_content()
        self.assertIn("[GPT 注册中心][普通流程] OpenAI 授权链路异常", message["Subject"])
        self.assertIn("链路：普通流程", body)
        self.assertIn("openai_tls_connection_failure", body)
        self.assertIn("中文原因：OpenAI TLS 握手失败", body)
        self.assertIn("sha256:0123456789abcdef", body)
        self.assertNotIn("smtp-secret-never-in-mail", rendered)
        self.assertNotIn("http://", rendered)

    def test_sticky_connectivity_message_names_the_fixed_batch_baseline(self):
        ssl_factory = FakeSmtpFactory()
        sender = SmtpNotificationSender(
            enabled_config(),
            smtp_ssl_factory=ssl_factory,
        )
        sender.send_connectivity(OpenAIConnectivityNotification(
            kind="recovery",
            event_id="incidentSticky",
            baseline=8,
            protocol_limit=8,
            healthy_ceiling=8,
            sticky_baseline=True,
        ))

        body = ssl_factory.clients[0].messages[0][0].get_content()
        self.assertIn("本批固定基线", body)
        self.assertNotIn("健康上限", body)

    def test_non_qq_transport_fields_cannot_change_delivery_target(self):
        ssl_factory = FakeSmtpFactory()
        sender = SmtpNotificationSender(
            enabled_config(
                provider="custom",
                host="smtp.example.test",
                port=2525,
                security="starttls",
            ),
            smtp_ssl_factory=ssl_factory,
        )
        sender.send(RunNotification(EVENT_STALLED, RunAggregate(active=1)))

        self.assertEqual(len(ssl_factory.clients), 1)
        client = ssl_factory.clients[0]
        self.assertEqual((client.host, client.port, client.timeout), ("smtp.qq.com", 465, 10))
        self.assertNotIn("starttls", client.calls)

    def test_message_builder_ignores_ids_secrets_and_raw_errors(self):
        sensitive = {
            "task_id": "TASK-PRIVATE-123",
            "account": "mailbox-private@example.test",
            "error": "raw-provider-failure-private",
            "sms_api_key": "sms-secret-private",
        }
        built = build_notification_message(
            enabled_config(),
            EVENT_UNEXPECTED_STOP,
            {"total": 2, "failed": 1, **sensitive},
        )
        message = built.as_string()

        self.assertIn("处理总数：2", built.get_content())
        self.assertIn("失败：1", built.get_content())
        for value in sensitive.values():
            self.assertNotIn(value, message)
        self.assertNotIn("smtp-secret", message)

    def test_unfinished_message_identifies_batch_tasks_and_safe_reason(self):
        built = build_notification_message(
            enabled_config(),
            EVENT_UNEXPECTED_STOP,
            {"total": 100, "succeeded": 53, "failed": 44, "active": 3},
            batch_id="20260808-150600-b20be0",
            unfinished_task_ids=("T058", "T078", "T083"),
            termination_reason="watch_returned_with_unfinished_tasks",
        )
        body = built.get_content()

        self.assertIn("运行异常（仍有任务未终态）", built["Subject"])
        self.assertIn("批次 20260808-150600-b20be0", built["Subject"])
        self.assertIn("未终态 3", built["Subject"])
        self.assertIn("共享批次：20260808-150600-b20be0", body)
        self.assertIn("未终态任务数：3", body)
        self.assertIn("未终态任务：T058、T078、T083", body)
        self.assertIn("批次监控正常返回，但仍有任务未终态", body)
        self.assertIn("这不是批次最终结果", body)

    def test_low_balance_message_contains_only_safe_key_identity(self):
        alert = SmsBalanceAlert(
            provider="smsbower",
            index=2,
            fingerprint="abcdef1234",
            balance_usd=0.42,
        )
        built = build_notification_message(
            enabled_config(),
            EVENT_SMS_BALANCE_LOW,
            RunAggregate(total=3, active=3),
            batch_id="20260810-1013",
            balance_alerts=[alert],
        )
        body = built.get_content()
        self.assertIn("SMS Key 余额不足", body)
        self.assertIn("平台 smsbower / Key 2", body)
        self.assertIn("指纹 abcdef1234", body)
        self.assertIn("当前余额 $0.4200", body)
        self.assertNotIn("api-secret", body)

    def test_notification_metadata_rejects_credentials_and_raw_reasons(self):
        private_values = (
            "mailbox-private@example.test",
            "raw provider failure: bearer-secret",
        )
        notification = RunNotification(
            EVENT_UNEXPECTED_STOP,
            RunAggregate(total=1, active=1),
            batch_id=private_values[0],
            unfinished_task_ids=("T058", private_values[0], "not-a-task"),
            termination_reason=private_values[1],
        )

        self.assertEqual(notification.batch_id, "")
        self.assertEqual(notification.unfinished_task_ids, ("T058",))
        self.assertEqual(notification.termination_reason, "")
        message = build_notification_message(
            enabled_config(),
            notification.event,
            notification.aggregate,
            batch_id=private_values[0],
            unfinished_task_ids=notification.unfinished_task_ids,
            termination_reason=private_values[1],
        ).as_string()
        for value in private_values:
            self.assertNotIn(value, message)

    def test_explicit_test_notification_has_safe_subject_and_body(self):
        factory = FakeSmtpFactory()

        result = send_test_notification(
            enabled_config(),
            smtp_ssl_factory=factory,
        )

        self.assertEqual(result["status"], "sent")
        message = factory.clients[0].messages[0][0]
        self.assertEqual(message["Subject"], "[GPT 注册中心] 测试通知")
        self.assertIn("配置测试成功", message.get_content())
        self.assertIn("普通流程", message.get_content())
        self.assertNotIn("smtp-secret", message.as_string())


class CoordinatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = FakeClock()
        self.notifications: list[RunNotification] = []
        self.coordinator = RunNotificationCoordinator(
            enabled_config(),
            self.notifications.append,
            clock=self.clock,
        )

    def test_batch_completion_is_at_most_once_for_run_id(self):
        aggregate = RunAggregate(total=3, succeeded=3)
        self.assertTrue(self.coordinator.start_run("sensitive-run-id", {"total": 3, "active": 3}))

        self.assertEqual(
            self.coordinator.finalize_run("sensitive-run-id", aggregate),
            (EVENT_BATCH_COMPLETED,),
        )
        self.assertEqual(self.coordinator.finalize_run("sensitive-run-id", aggregate), ())
        self.assertFalse(self.coordinator.start_run("sensitive-run-id", aggregate))
        self.assertEqual([item.event for item in self.notifications], [EVENT_BATCH_COMPLETED])
        self.assertFalse(hasattr(self.notifications[0], "run_id"))

    def test_incomplete_finalize_alerts_without_freezing_final_summary(self):
        self.coordinator.start_run(
            "run-a",
            RunAggregate(total=2, active=2),
            batch_id="20260808-150600-b20be0",
        )
        result = self.coordinator.finalize_run(
            "run-a",
            RunAggregate(total=2, failed=1, active=1),
            completed=False,
            unfinished_task_ids=("T058",),
            termination_reason="watch_returned_with_unfinished_tasks",
        )
        self.assertEqual(result, (EVENT_UNEXPECTED_STOP,))
        self.assertEqual(self.notifications[0].event, EVENT_UNEXPECTED_STOP)
        self.assertEqual(self.notifications[0].batch_id, "20260808-150600-b20be0")
        self.assertEqual(self.notifications[0].unfinished_task_ids, ("T058",))
        self.assertEqual(
            self.notifications[0].termination_reason,
            "watch_returned_with_unfinished_tasks",
        )
        self.assertEqual(self.coordinator.public_status()["active_runs"], 1)
        self.assertEqual(
            self.coordinator.finalize_run(
                "run-a",
                RunAggregate(total=2, failed=1, active=1),
                completed=False,
                unfinished_task_ids=("T058",),
            ),
            (),
        )

        finished = RunAggregate(total=2, succeeded=1, failed=1)
        self.assertEqual(
            self.coordinator.finalize_run("run-a", finished),
            (EVENT_BATCH_COMPLETED,),
        )
        self.assertEqual(
            [item.event for item in self.notifications],
            [EVENT_UNEXPECTED_STOP, EVENT_BATCH_COMPLETED],
        )
        self.assertEqual(self.coordinator.public_status()["active_runs"], 0)

    def test_completed_flag_cannot_finalize_an_unfinished_aggregate(self):
        self.coordinator.start_run("run-a", RunAggregate(total=1, active=1))

        result = self.coordinator.finalize_run(
            "run-a",
            RunAggregate(total=1, active=1),
            completed=True,
            unfinished_task_ids=("T001-ab12cd",),
        )

        self.assertEqual(result, (EVENT_UNEXPECTED_STOP,))
        self.assertEqual(self.notifications[0].event, EVENT_UNEXPECTED_STOP)
        self.assertEqual(self.coordinator.public_status()["active_runs"], 1)

    def test_terminal_unexpected_stop_is_final(self):
        self.coordinator.start_run("run-a", RunAggregate(total=1, active=1))
        terminal = RunAggregate(total=1, failed=1)

        self.assertEqual(
            self.coordinator.finalize_run(
                "run-a",
                terminal,
                completed=False,
                termination_reason="watch_failed",
            ),
            (EVENT_UNEXPECTED_STOP,),
        )
        self.assertEqual(self.coordinator.public_status()["active_runs"], 0)
        self.assertEqual(self.coordinator.finalize_run("run-a", terminal), ())

    def test_manual_stop_default_suppresses_both_manual_and_unexpected_mail(self):
        aggregate = RunAggregate(total=2, active=2)
        self.coordinator.start_run("run-a", aggregate)

        self.assertEqual(self.coordinator.mark_manual_stop("run-a", aggregate), ())
        self.assertEqual(
            self.coordinator.finalize_run("run-a", aggregate, completed=False),
            (),
        )
        self.assertEqual(self.notifications, [])
        status = self.coordinator.public_status()
        self.assertEqual(status["triggered_events"][EVENT_MANUAL_STOP], 1)
        self.assertEqual(status["triggered_events"][EVENT_UNEXPECTED_STOP], 0)

    def test_enabled_manual_stop_is_sent_only_once(self):
        config = enabled_config(events={EVENT_MANUAL_STOP: True})
        coordinator = RunNotificationCoordinator(config, self.notifications.append)
        aggregate = RunAggregate(total=1, active=1)
        coordinator.start_run("run-a", aggregate)

        self.assertEqual(coordinator.mark_manual_stop("run-a", aggregate), ())
        self.assertEqual(coordinator.mark_manual_stop("run-a", aggregate), ())
        final = RunAggregate(total=1, stopped=1)
        self.assertEqual(
            coordinator.finalize_run("run-a", final, completed=False),
            (EVENT_MANUAL_STOP,),
        )
        self.assertEqual([item.event for item in self.notifications], [EVENT_MANUAL_STOP])
        self.assertEqual(self.notifications[0].aggregate, final)

    def test_progress_resets_stall_timer_and_stall_is_at_most_once(self):
        self.coordinator.start_run("run-a", RunAggregate(total=2, active=1, pending=1))
        self.clock.value = 599
        self.assertEqual(
            self.coordinator.observe_run(
                "run-a",
                RunAggregate(total=2, succeeded=1, active=1),
            ),
            (),
        )
        self.clock.value = 1198
        self.assertEqual(
            self.coordinator.check_stall(
                "run-a",
                RunAggregate(total=2, succeeded=1, active=1),
            ),
            (),
        )
        self.clock.value = 1199
        self.assertEqual(
            self.coordinator.check_stall(
                "run-a",
                RunAggregate(total=2, succeeded=1, active=1),
            ),
            (EVENT_STALLED,),
        )
        self.clock.value = 2000
        self.assertEqual(
            self.coordinator.check_stall(
                "run-a",
                RunAggregate(total=2, succeeded=1, active=1),
            ),
            (),
        )
        self.assertEqual([item.event for item in self.notifications], [EVENT_STALLED])

    def test_completed_aggregate_never_triggers_stall(self):
        aggregate = RunAggregate(total=1, succeeded=1)
        self.coordinator.start_run("run-a", aggregate)
        self.clock.value = 5000
        self.assertEqual(self.coordinator.check_stall("run-a", aggregate), ())

    def test_elapsed_duration_alone_does_not_reset_stall_timer(self):
        self.coordinator.start_run(
            "run-a",
            RunAggregate(total=1, active=1, duration_seconds=0),
        )
        self.clock.value = 600

        result = self.coordinator.check_stall(
            "run-a",
            RunAggregate(total=1, active=1, duration_seconds=600),
        )

        self.assertEqual(result, (EVENT_STALLED,))
        self.assertEqual([item.event for item in self.notifications], [EVENT_STALLED])

    def test_connectivity_outage_freezes_stall_elapsed_time(self):
        aggregate = RunAggregate(total=1, active=1)
        self.coordinator.start_run("run-a", aggregate)
        self.clock.value = 590
        self.coordinator.set_stall_suspended(True)
        self.clock.value = 1000
        self.assertEqual(self.coordinator.check_stall("run-a", aggregate), ())
        self.coordinator.set_stall_suspended(False)
        self.clock.value = 1009
        self.assertEqual(self.coordinator.check_stall("run-a", aggregate), ())
        self.clock.value = 1010
        self.assertEqual(
            self.coordinator.check_stall("run-a", aggregate),
            (EVENT_STALLED,),
        )

    def test_progress_during_outage_restarts_stall_timer_at_recovery(self):
        aggregate = RunAggregate(total=2, active=1, pending=1)
        self.coordinator.start_run("run-a", aggregate)
        self.clock.value = 10
        self.coordinator.set_stall_suspended(True)
        self.clock.value = 50
        progressed = RunAggregate(total=2, succeeded=1, active=1)
        self.coordinator.observe_run("run-a", progressed)
        self.clock.value = 100
        self.coordinator.set_stall_suspended(False)

        self.clock.value = 699
        self.assertEqual(self.coordinator.check_stall("run-a", progressed), ())
        self.clock.value = 700
        self.assertEqual(
            self.coordinator.check_stall("run-a", progressed),
            (EVENT_STALLED,),
        )

    def test_sms_exhaustion_is_at_most_once(self):
        aggregate = RunAggregate(total=2, active=1, pending=1)
        self.coordinator.start_run("run-a", aggregate)
        self.assertEqual(
            self.coordinator.observe_sms_exhausted("run-a", aggregate),
            (EVENT_SMS_EXHAUSTED,),
        )
        self.assertEqual(
            self.coordinator.observe_run("run-a", aggregate, sms_exhausted=True),
            (),
        )
        self.assertEqual([item.event for item in self.notifications], [EVENT_SMS_EXHAUSTED])

    def test_sms_exhaustion_alert_does_not_replace_final_summary(self):
        running = RunAggregate(total=1, active=1)
        finished = RunAggregate(total=1, failed=1)
        self.coordinator.start_run("run-a", running)

        self.assertEqual(
            self.coordinator.observe_run("run-a", running, sms_exhausted=True),
            (EVENT_SMS_EXHAUSTED,),
        )
        self.assertEqual(
            self.coordinator.finalize_run("run-a", finished),
            (EVENT_BATCH_COMPLETED,),
        )
        self.assertEqual(
            [item.event for item in self.notifications],
            [EVENT_SMS_EXHAUSTED, EVENT_BATCH_COMPLETED],
        )

    def test_low_balance_alert_is_deduplicated_by_provider_and_fingerprint(self):
        self.coordinator.start_run("run-a", RunAggregate(total=2, active=2))
        statuses = [
            {
                "provider": "smsbower",
                "index": 1,
                "fingerprint": "aaaaaaaaaa",
                "balance_usd": 0.8,
            },
            {
                "provider": "smsbower",
                "index": 1,
                "fingerprint": "aaaaaaaaaa",
                "balance_usd": 0.8,
            },
            {
                "provider": "herosms",
                "index": 3,
                "fingerprint": "bbbbbbbbbb",
                "balance_usd": 0.2,
            },
        ]
        self.assertEqual(
            self.coordinator.observe_sms_balances(
                "run-a",
                RunAggregate(active=2),
                statuses,
            ),
            (EVENT_SMS_BALANCE_LOW,),
        )
        self.assertEqual(len(self.notifications), 1)
        self.assertEqual(
            {(item.provider, item.fingerprint) for item in self.notifications[0].balance_alerts},
            {("smsbower", "aaaaaaaaaa"), ("herosms", "bbbbbbbbbb")},
        )
        self.assertEqual(
            self.coordinator.observe_sms_balances("run-a", RunAggregate(active=2), statuses),
            (),
        )
        self.assertEqual(
            self.coordinator.public_status()["triggered_events"][EVENT_SMS_BALANCE_LOW],
            1,
        )

    def test_low_balance_alert_ignores_disabled_and_invalid_balance_rows(self):
        self.coordinator.start_run("run-a", RunAggregate(total=1, active=1))
        statuses = [
            {
                "provider": "smsbower",
                "index": 1,
                "fingerprint": "aaaaaaaaaa",
                "balance_usd": 0.2,
                "enabled": False,
            },
            {
                "provider": "herosms",
                "index": 2,
                "fingerprint": "bbbbbbbbbb",
                "balance_usd": -0.1,
                "enabled": True,
            },
        ]

        self.assertEqual(
            self.coordinator.observe_sms_balances(
                "run-a",
                RunAggregate(total=1, active=1),
                statuses,
            ),
            (),
        )
        self.assertEqual(self.notifications, [])
        with self.assertRaises(ValueError):
            SmsBalanceAlert(
                provider="smsbower",
                index=1,
                fingerprint="aaaaaaaaaa",
                balance_usd=-0.1,
            )

    def test_unknown_and_finalized_runs_ignore_observations(self):
        running = RunAggregate(total=1, active=1)
        finished = RunAggregate(total=1, succeeded=1)
        self.assertEqual(self.coordinator.observe_run("unknown", running), ())
        self.coordinator.start_run("run-a", running)
        self.coordinator.finalize_run("run-a", finished)
        self.notifications.clear()
        self.assertEqual(
            self.coordinator.observe_run("run-a", finished, sms_exhausted=True),
            (),
        )

    def test_public_status_contains_counts_but_no_run_ids(self):
        private_id = "private-run-identifier"
        self.coordinator.start_run(private_id, RunAggregate(active=1))
        status = self.coordinator.public_status()
        self.assertEqual(status["active_runs"], 1)
        self.assertEqual(status["tracked_runs"], 1)
        self.assertNotIn(private_id, str(status))


class QueueTests(unittest.TestCase):
    def test_queue_is_bounded_at_sixteen_and_worker_is_daemon(self):
        created_threads = []

        class DormantThread:
            def __init__(self, **kwargs):
                self.kwargs = kwargs
                self.started = False
                created_threads.append(self)

            def start(self):
                self.started = True

            def is_alive(self):
                return self.started

            def join(self, timeout=None):
                return None

        dispatcher = NotificationQueue(
            lambda _item: None,
            thread_factory=DormantThread,
            now_fn=lambda: 1234,
        )
        notification = RunNotification(EVENT_STALLED, RunAggregate(active=1))

        for _index in range(NOTIFICATION_QUEUE_CAPACITY):
            self.assertTrue(dispatcher.submit(notification))
        self.assertFalse(dispatcher.submit(notification))

        self.assertEqual(len(created_threads), 1)
        self.assertTrue(created_threads[0].kwargs["daemon"])
        self.assertEqual(created_threads[0].kwargs["name"], "run-notification-email")
        status = dispatcher.public_status()
        self.assertEqual(status["queue_capacity"], 16)
        self.assertEqual(status["queue_depth"], 16)
        self.assertEqual(status["submitted"], 16)
        self.assertEqual(status["dropped"], 1)
        self.assertEqual(status["event"], EVENT_STALLED)
        self.assertEqual(status["status"], "failed")
        self.assertEqual(status["timestamp"], 1234)
        dispatcher.close(wait=False)

    def test_failure_is_not_retried_and_does_not_stop_later_delivery(self):
        attempts: list[str] = []

        def send(notification):
            attempts.append(notification.event)
            if notification.event == EVENT_STALLED:
                raise RuntimeError("private SMTP diagnostic")

        dispatcher = NotificationQueue(send)
        dispatcher.submit(RunNotification(EVENT_STALLED, RunAggregate(active=1)))
        dispatcher.submit(RunNotification(EVENT_SMS_EXHAUSTED, RunAggregate(active=1)))

        self.assertTrue(dispatcher.wait_until_idle(1))
        status = dispatcher.public_status()
        self.assertEqual(attempts, [EVENT_STALLED, EVENT_SMS_EXHAUSTED])
        self.assertEqual(status["failed"], 1)
        self.assertEqual(status["sent"], 1)
        self.assertEqual(status["last_result"], "sent")
        self.assertNotIn("private SMTP diagnostic", str(status))
        dispatcher.close()

    def test_submit_after_close_is_dropped(self):
        dispatcher = NotificationQueue(lambda _item: None)
        dispatcher.close()
        accepted = dispatcher.submit(
            RunNotification(EVENT_BATCH_COMPLETED, RunAggregate(total=1, succeeded=1))
        )
        self.assertFalse(accepted)
        self.assertEqual(dispatcher.public_status()["dropped"], 1)


class ServiceTests(unittest.TestCase):
    @staticmethod
    def connectivity_notification():
        return OpenAIConnectivityNotification(
            kind="outage",
            event_id="incident123",
            reason_code="openai_proxy_connection_failure",
            affected_origins=("auth.openai.com",),
            baseline=8,
            protocol_limit=8,
            healthy_ceiling=12,
        )

    def test_service_delivers_through_injected_smtp_and_exposes_safe_status(self):
        ssl_factory = FakeSmtpFactory()
        service = RunNotificationService(
            enabled_config(password="service-private-password"),
            smtp_ssl_factory=ssl_factory,
        )
        private_run_id = "private-run-id"
        service.start_run(private_run_id, RunAggregate(total=1, active=1))
        service.finalize_run(private_run_id, RunAggregate(total=1, succeeded=1))

        self.assertTrue(service.wait_until_idle(1))
        status = service.public_status()
        self.assertEqual(status["sent"], 1)
        self.assertEqual(status["active_runs"], 0)
        self.assertEqual(status["recipient_count"], 1)
        self.assertEqual(status["event"], EVENT_BATCH_COMPLETED)
        self.assertEqual(status["status"], "sent")
        self.assertNotIn(private_run_id, str(status))
        self.assertNotIn("service-private-password", str(status))
        self.assertEqual(len(ssl_factory.clients), 1)
        service.close()

    def test_disabled_service_never_starts_worker_or_sends(self):
        service = RunNotificationService({"enabled": False})
        service.start_run("run-a", RunAggregate(total=1, active=1))
        self.assertEqual(
            service.finalize_run("run-a", RunAggregate(total=1, succeeded=1)),
            (),
        )
        status = service.public_status()
        self.assertFalse(status["enabled"])
        self.assertFalse(status["worker_running"])
        self.assertEqual(status["submitted"], 0)
        service.close()

    def test_connectivity_event_switch_and_smtp_failure_never_escape(self):
        disabled = OpenAIConnectivityNotificationService(
            lambda: enabled_config(events={EVENT_OPENAI_AUTH_CONNECTIVITY: False})
        )
        self.assertFalse(disabled.submit(self.connectivity_notification()))
        self.assertEqual(disabled.public_status()["submitted"], 0)
        disabled.close()

        def failing_smtp(*_args, **_kwargs):
            raise RuntimeError("smtp private failure")

        service = OpenAIConnectivityNotificationService(
            lambda: enabled_config(),
            smtp_ssl_factory=failing_smtp,
        )
        self.assertTrue(service.submit(self.connectivity_notification()))
        self.assertTrue(service.dispatcher.wait_until_idle(1))
        status = service.public_status()
        self.assertEqual(status["failed"], 1)
        self.assertNotIn("smtp private failure", str(status))
        service.close()


if __name__ == "__main__":
    unittest.main()
