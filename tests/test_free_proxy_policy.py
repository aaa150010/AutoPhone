from __future__ import annotations

from pathlib import Path
import tempfile
import time
import unittest

from mac_overrides.free_proxy_health import is_proxy_health_failure
from mac_overrides.free_register_common import FreeRegisterError, normalize_proxy_value
from mac_overrides.free_register_runtime import FreeRegisterManager


class FreeProxyParsingTests(unittest.TestCase):
    def test_invalid_percent_escapes_are_rejected_in_every_input_layout(self):
        invalid = (
            "socks5://user%:pass@proxy.test:3000",
            "socks5://user%2:pass@proxy.test:3000",
            "socks5://user%GG:pass@proxy.test:3000",
            "proxy.test:3000:user:pass%",
            "user:pass%XZ@proxy.test:3000",
            "proxy.test:3000@user%1:pass",
            "proxy%.test:3000",
        )
        for value in invalid:
            with self.subTest(value=value):
                self.assertEqual(normalize_proxy_value(value), "")

    def test_legal_url_encoding_ipv6_and_ports_are_preserved(self):
        self.assertEqual(
            normalize_proxy_value("socks5://user%40mail:p%25ss@[2001:db8::1]:65535"),
            "socks5://user%40mail:p%25ss@[2001:db8::1]:65535",
        )
        self.assertEqual(
            normalize_proxy_value("user%40mail:p%25ss@[::1]:1"),
            "http://user%40mail:p%25ss@[::1]:1",
        )
        self.assertEqual(
            normalize_proxy_value("http://[fe80::1%25en0]:8080"),
            "http://[fe80::1%25en0]:8080",
        )
        self.assertEqual(normalize_proxy_value("http://proxy.test:0"), "")
        self.assertEqual(normalize_proxy_value("http://proxy.test:65536"), "")


class FreeProxyHealthTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="gptphone-free-proxy-policy-")
        self.manager = FreeRegisterManager(Path(self.temporary.name))
        self.manager.proxies.import_text("http://proxy-a.test:8000\n")
        self.proxy_id = self.manager.proxies.public()["rows"][0]["proxy_id"]
        self.task = {"task_id": "free-task", "proxy_id": self.proxy_id}
        self.manager._tasks["free-task"] = dict(self.task)

    def tearDown(self):
        self.temporary.cleanup()

    def failures(self) -> int:
        return self.manager.proxies.public()["rows"][0]["consecutive_failures"]

    def test_binding_format_and_missing_value_do_not_reduce_health(self):
        failures = (
            FreeRegisterError("free_proxy_binding", "绑定 Free 注册代理", "任务缺少固定代理绑定", retryable=False),
            FreeRegisterError("free_proxy_binding", "绑定 Free 注册代理", "代理格式无效", retryable=False),
            FreeRegisterError("free_proxy_binding", "绑定 Free 注册代理", "代理端口缺失", retryable=False),
            FreeRegisterError(
                "free_proxy_binding", "绑定 Free 注册代理", "代理请求超时配置格式无效",
                retryable=False, error_code="proxy_timeout_config_invalid",
            ),
        )
        for failure in failures:
            self.manager._record_proxy_failure(
                self.task,
                failure,
            )
        self.assertEqual(self.failures(), 0)

    def test_only_explicit_proxy_network_evidence_reduces_health(self):
        class ProxyError(RuntimeError):
            pass

        outer = FreeRegisterError("free_proxy_binding", "绑定 Free 注册代理", "固定代理出口复核失败")
        outer.__cause__ = ProxyError("proxy CONNECT failed")
        self.assertTrue(is_proxy_health_failure(outer))
        self.manager._record_proxy_failure(self.task, outer)
        self.assertEqual(self.failures(), 1)

        drift = FreeRegisterError("free_proxy_drift", "校验 Free 代理出口", "实际出口与预绑定出口不一致")
        self.manager._record_proxy_failure(self.task, drift)
        self.assertEqual(self.failures(), 1)

    def test_verify_accepts_exit_ip_rotation_and_updates_current_ip(self):
        binding = self.manager.proxies.bind(
            1,
            probe=lambda _proxy, _url: "203.0.113.10",
        )[0]
        current = self.manager.proxies.verify(
            binding,
            probe=lambda _proxy, _url: "203.0.113.99",
        )
        self.assertEqual(current, "203.0.113.99")
        self.assertNotIn("last_exit_ip", self.manager.proxies.public()["rows"][0])

    def test_auth_dns_tls_timeout_and_roxy_exit_evidence_are_classified(self):
        failures = (
            FreeRegisterError("free_proxy_binding", "绑定 Free 注册代理", "代理认证被拒绝 HTTP 407"),
            FreeRegisterError("free_proxy_binding", "绑定 Free 注册代理", "代理域名解析失败"),
            FreeRegisterError("free_proxy_preflight", "Free 代理预检", "TLS/证书握手失败"),
            FreeRegisterError("free_protocol_preflight", "协议网络预检", "ChatGPT 连接超时"),
            FreeRegisterError("free_oauth_session", "Free OAuth 会话", "代理 CONNECT 失败"),
            FreeRegisterError("free_proxy_preflight", "Free 代理预检", "连接超时"),
            FreeRegisterError("free_roxy_ip_verify", "校验 RoxyBrowser 出口 IP", "出口响应格式无效"),
        )
        self.assertTrue(all(is_proxy_health_failure(failure) for failure in failures))

    def test_http_5xx_is_proxy_health_evidence_but_429_and_business_4xx_are_not(self):
        for status in (500, 502, 503, 504, 599):
            with self.subTest(status=status):
                failure = FreeRegisterError(
                    "free_proxy_preflight",
                    "Free 代理预检",
                    f"代理探测请求返回 HTTP {status}",
                    provider_status=status,
                )
                self.assertTrue(is_proxy_health_failure(failure))
        for status in (400, 401, 403, 404, 409, 429):
            with self.subTest(status=status):
                failure = FreeRegisterError(
                    "free_proxy_preflight",
                    "Free 代理预检",
                    f"代理探测请求返回 HTTP {status}",
                    provider_status=status,
                )
                self.assertFalse(is_proxy_health_failure(failure))
        auth_failure = FreeRegisterError(
            "free_proxy_preflight",
            "Free 代理预检",
            "代理探测请求返回 HTTP 407",
            provider_status=407,
        )
        self.assertTrue(is_proxy_health_failure(auth_failure))

        # An explicit business status wins over incidental transport wording
        # that may be present in a provider's diagnostic message.
        business_failure = FreeRegisterError(
            "free_proxy_preflight",
            "Free 代理预检",
            "业务拒绝（proxy connect policy；HTTP 403）",
            provider_status=403,
        )
        self.assertFalse(is_proxy_health_failure(business_failure))

    def test_localized_http_5xx_text_is_classified_without_status_field(self):
        failure = FreeRegisterError(
            "free_proxy_preflight",
            "Free 代理预检",
            "代理探测请求返回 HTTP 503",
        )
        self.assertTrue(is_proxy_health_failure(failure))

    def test_camoufox_context_proxy_retry_is_classified_as_proxy_evidence(self):
        failure = FreeRegisterError(
            "free_camoufox_launch",
            "创建 Camoufox 浏览器 context",
            "Camoufox context 创建失败",
            error_code="camoufox_context_create_failed",
        )
        failure.proxy_retryable = True
        self.assertTrue(is_proxy_health_failure(failure))

        runtime_failure = FreeRegisterError(
            "free_camoufox_launch",
            "启动 Camoufox 浏览器池",
            "浏览器运行时不可用",
            error_code="camoufox_context_create_failed",
        )
        runtime_failure.proxy_retryable = False
        self.assertFalse(is_proxy_health_failure(runtime_failure))

    def test_page_otp_account_challenge_and_lease_failures_never_reduce_health(self):
        page_failure = FreeRegisterError("free_roxy_signup_email_submit", "测试节点", "页面提交超时")
        page_failure.__cause__ = ConnectionError("proxy connection timeout")
        failures = (
            page_failure,
            ("free_email_otp_wait", "验证码请求超时"),
            ("free_account_create", "账号创建连接超时"),
            ("free_oauth_security_challenge", "安全挑战等待超时"),
            ("free_proxy_lease", "独占代理或出口 IP 已被其他任务租用"),
        )
        for value in failures:
            failure = value if isinstance(value, BaseException) else FreeRegisterError(value[0], "测试节点", value[1])
            self.manager._record_proxy_failure(
                self.task,
                failure,
            )
        self.assertEqual(self.failures(), 0)

    def test_protocol_network_failure_switches_before_email_submission(self):
        probe_calls = 0
        attempts: list[tuple[str, str]] = []

        def probe(proxy, _url):
            nonlocal probe_calls
            probe_calls += 1
            return "203.0.113.10" if "proxy-a" in proxy else "203.0.113.11"

        def runner(task, _config, _stop, _stage, _log, *, twofa_retry=False):
            self.assertFalse(twofa_retry)
            attempts.append((str(task.get("proxy_id") or ""), str(task.get("device_id") or "")))
            if len(attempts) == 1:
                failure = FreeRegisterError(
                    "free_protocol_preflight", "协议网络预检", "ChatGPT 连接超时",
                )
                failure.__cause__ = ConnectionError("proxy CONNECT timeout")
                raise failure
            return {"access_token": "token-private", "twofa_status": "disabled"}

        manager = FreeRegisterManager(Path(self.temporary.name), runner=runner, proxy_probe=probe)
        manager.start(
            {"driver": "protocol", "target_count": 1, "concurrency": 1, "proxy_retry_count": 1},
            pool_content="user@example.test----https://mail.example.test/inbox\n",
            proxy_content="http://proxy-a.test:8000\nhttp://proxy-b.test:8000\n",
        )
        deadline = time.time() + 3
        while manager.public_state()["running"] and time.time() < deadline:
            time.sleep(0.01)

        task = manager.public_tasks()[0]
        self.assertEqual(task["status"], "success")
        self.assertEqual(len(attempts), 2)
        self.assertNotEqual(attempts[0][0], attempts[1][0])
        self.assertTrue(attempts[0][1])
        self.assertEqual(attempts[0][1], attempts[1][1])
        self.assertEqual(probe_calls, 0)
        self.assertEqual(
            sorted(row["consecutive_failures"] for row in manager.proxies.public()["rows"]),
            [0, 1],
        )

    def test_protocol_preflight_access_denied_switches_route_without_quarantining_proxy(self):
        attempts: list[str] = []

        def runner(task, _config, _stop, _stage, _log, *, twofa_retry=False):
            self.assertFalse(twofa_retry)
            attempts.append(str(task.get("proxy_id") or ""))
            if len(attempts) == 1:
                failure = FreeRegisterError(
                    "free_protocol_preflight", "协议网络预检", "chatgpt-login 预检返回 HTTP 403",
                    provider_status=403, retryable=True,
                )
                failure.proxy_retryable = True
                raise failure
            return {"access_token": "token-private", "twofa_status": "disabled"}

        manager = FreeRegisterManager(
            Path(self.temporary.name),
            runner=runner,
            proxy_probe=lambda proxy, _url: "203.0.113.10" if "proxy-a" in proxy else "203.0.113.11",
        )
        manager.start(
            {"driver": "protocol", "target_count": 1, "concurrency": 1, "proxy_retry_count": 1},
            pool_content="user@example.test----https://mail.example.test/inbox\n",
            proxy_content="http://proxy-a.test:8000\nhttp://proxy-b.test:8000\n",
        )
        deadline = time.time() + 3
        while manager.public_state()["running"] and time.time() < deadline:
            time.sleep(0.01)

        task = manager.public_tasks()[0]
        self.assertEqual(task["status"], "success")
        self.assertEqual(len(attempts), 2)
        self.assertNotEqual(attempts[0], attempts[1])
        self.assertEqual(
            sorted(row["consecutive_failures"] for row in manager.proxies.public()["rows"]),
            [0, 0],
        )

    def test_camoufox_context_failure_switches_proxy_before_email_submission(self):
        attempts: list[str] = []

        def runner(task, _config, _stop, _stage, _log, *, twofa_retry=False):
            self.assertFalse(twofa_retry)
            attempts.append(str(task.get("proxy_id") or ""))
            if len(attempts) == 1:
                failure = FreeRegisterError(
                    "free_camoufox_launch",
                    "创建 Camoufox 浏览器 context",
                    "Camoufox context 创建失败",
                    error_code="camoufox_context_create_failed",
                )
                failure.proxy_retryable = True
                raise failure
            return {
                "access_token": "token-private",
                "twofa_status": "enabled",
                "totp_secret": "JBSWY3DPEHPK3PXP",
            }

        manager = FreeRegisterManager(
            Path(self.temporary.name),
            runner=runner,
            proxy_probe=lambda proxy, _url: "203.0.113.10" if "proxy-a" in proxy else "203.0.113.11",
        )
        manager.start(
            {"driver": "camoufox", "target_count": 1, "concurrency": 1, "proxy_retry_count": 1},
            pool_content="user@example.test----https://mail.example.test/inbox\n",
            proxy_content="http://proxy-a.test:8000\nhttp://proxy-b.test:8000\n",
        )
        deadline = time.time() + 3
        while manager.public_state()["running"] and time.time() < deadline:
            time.sleep(0.01)

        task = manager.public_tasks()[0]
        self.assertEqual(task["status"], "success")
        self.assertEqual(len(attempts), 2)
        self.assertNotEqual(attempts[0], attempts[1])
        self.assertEqual(
            sorted(row["consecutive_failures"] for row in manager.proxies.public()["rows"]),
            [0, 1],
        )

    def test_protocol_failure_after_email_submission_keeps_fixed_proxy(self):
        attempts: list[str] = []

        def runner(task, _config, _stop, _stage, _log, *, twofa_retry=False):
            self.assertFalse(twofa_retry)
            attempts.append(str(task.get("proxy_id") or ""))
            failure = FreeRegisterError(
                "free_email_identifier", "识别 Free 注册邮箱", "邮箱提交后连接超时",
            )
            failure.__cause__ = ConnectionError("proxy CONNECT timeout")
            raise failure

        manager = FreeRegisterManager(
            Path(self.temporary.name),
            runner=runner,
            proxy_probe=lambda proxy, _url: "203.0.113.10" if "proxy-a" in proxy else "203.0.113.11",
        )
        manager.start(
            {"driver": "protocol", "target_count": 1, "concurrency": 1, "proxy_retry_count": 1},
            pool_content="user@example.test----https://mail.example.test/inbox\n",
            proxy_content="http://proxy-a.test:8000\nhttp://proxy-b.test:8000\n",
        )
        deadline = time.time() + 3
        while manager.public_state()["running"] and time.time() < deadline:
            time.sleep(0.01)

        task = manager.public_tasks()[0]
        self.assertEqual(task["status"], "failed")
        self.assertEqual(len(attempts), 1)
        self.assertEqual(
            sum(row["consecutive_failures"] for row in manager.proxies.public()["rows"]),
            0,
        )


if __name__ == "__main__":
    unittest.main()
