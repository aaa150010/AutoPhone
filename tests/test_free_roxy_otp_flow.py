"""Fake-Selenium coverage for the Free Roxy email OTP page state machine."""

from __future__ import annotations

import unittest
from unittest.mock import patch

from mac_overrides.free_register_common import FreeRegisterError


class _FakeOtpElement:
    def __init__(
        self,
        *,
        value: str = "",
        visible: bool = True,
        enabled: bool = True,
        input_type: str = "text",
        name: str = "",
        element_id: str = "",
        autocomplete: str = "",
        inputmode: str = "",
        aria_label: str = "",
        placeholder: str = "",
        testid: str = "",
        maxlength: str = "",
    ) -> None:
        self.value = value
        self.visible = visible
        self.enabled = enabled
        self.attrs = {
            "type": input_type,
            "name": name,
            "id": element_id,
            "autocomplete": autocomplete,
            "inputmode": inputmode,
            "aria-label": aria_label,
            "placeholder": placeholder,
            "data-testid": testid,
            "maxlength": maxlength,
        }
        self.sent: list[str] = []
        self.clicked = 0

    def is_displayed(self) -> bool:
        return self.visible

    def is_enabled(self) -> bool:
        return self.enabled

    def get_attribute(self, name: str) -> str:
        if name == "value":
            return self.value
        return self.attrs.get(name, "")

    def clear(self) -> None:
        self.value = ""

    def send_keys(self, *values: object) -> None:
        for value in values:
            text = str(value)
            self.sent.append(text)
            if text in {"\ue003", "\ue009"}:
                if text == "\ue003":
                    self.value = ""
                continue
            self.value += text

    def click(self) -> None:
        self.clicked += 1


class _FakeOtpDriver:
    def __init__(self, elements: list[_FakeOtpElement], *, body: str = "") -> None:
        self.elements = elements
        self.body = body
        self.current_url = "https://auth.openai.com/email-verification"
        self.find_calls = 0
        self.submit_probe = {
            "submit_observed": False,
            "status": None,
            "content_type": "",
            "error_code": "",
        }

    def find_elements(self, _by: object, _selector: str) -> list[_FakeOtpElement]:
        self.find_calls += 1
        return list(self.elements)

    def find_element(self, _by: object, _selector: str) -> _FakeOtpElement:
        return type("Body", (), {"text": self.body})()

    def execute_script(self, script: str, *_args: object) -> object:
        lowered = str(script).lower()
        if "otp" in lowered and "submit" in lowered and "probe" in lowered:
            return dict(self.submit_probe)
        if "__gptphone" in lowered and "submit_observed" in lowered:
            return dict(self.submit_probe)
        if "aria-invalid" in lowered or "const errors" in lowered:
            return {
                "url": self.current_url,
                "inputs": [
                    {
                        "type": element.attrs["type"],
                        "name": element.attrs["name"],
                        "id": element.attrs["id"],
                        "autocomplete": element.attrs["autocomplete"],
                        "inputmode": element.attrs["inputmode"],
                        "aria_label": element.attrs["aria-label"],
                        "placeholder": element.attrs["placeholder"],
                        "maxlength": element.attrs["maxlength"],
                        "aria_invalid": "",
                    }
                    for element in self.elements
                ],
                "errors": [self.body] if self.body else [],
            }
        if "document.body" in lowered and "innertext" in lowered:
            return {
                "title": "Verify your email",
                "body": self.body,
                "inputs": [
                    {
                        "type": element.attrs["type"],
                        "name": element.attrs["name"],
                        "id": element.attrs["id"],
                        "autocomplete": element.attrs["autocomplete"],
                        "aria": element.attrs["aria-label"],
                        "placeholder": element.attrs["placeholder"],
                        "inputmode": element.attrs["inputmode"],
                        "maxlength": element.attrs["maxlength"],
                    }
                    for element in self.elements
                ],
            }
        return False


class FreeRoxyOtpFlowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        # The module is deliberately imported here so unrelated legacy tests can
        # still run while a deployment is being upgraded to the new runtime.
        from mac_overrides import free_roxy_otp_flow

        cls.flow = free_roxy_otp_flow

    def test_find_inputs_matches_accessible_otp_attributes_and_skips_hidden(self) -> None:
        fields = [
            _FakeOtpElement(
                input_type="tel",
                aria_label="Verification code",
                placeholder="Enter code",
            ),
            _FakeOtpElement(
                visible=False,
                input_type="tel",
                aria_label="Verification code",
            ),
            _FakeOtpElement(input_type="text", name="display_name"),
        ]
        driver = _FakeOtpDriver(fields)

        result = self.flow.find_otp_inputs(driver)

        self.assertEqual(result, [fields[0]])

    def test_active_auth_window_is_selected_over_unrelated_tab(self) -> None:
        class Switch:
            def __init__(self, driver):
                self.driver = driver

            def window(self, handle):
                self.driver.current_window_handle = handle
                self.driver.current_url = self.driver.urls[handle]

        class WindowDriver(_FakeOtpDriver):
            def __init__(self):
                super().__init__([])
                self.urls = {
                    "tab-settings": "https://example.test/blank",
                    "tab-auth": "https://auth.openai.com/email-verification",
                }
                self.window_handles = list(self.urls)
                self.current_window_handle = "tab-settings"
                self.current_url = self.urls[self.current_window_handle]
                self.switch_to = Switch(self)

        driver = WindowDriver()
        self.flow.select_active_auth_window(driver)

        self.assertEqual(driver.current_window_handle, "tab-auth")
        self.assertEqual(driver.current_url, "https://auth.openai.com/email-verification")

    def test_active_auth_window_can_prefer_profile_stage(self) -> None:
        class Switch:
            def __init__(self, driver):
                self.driver = driver

            def window(self, handle):
                self.driver.current_window_handle = handle
                self.driver.current_url = self.driver.urls[handle]

        class WindowDriver(_FakeOtpDriver):
            def __init__(self):
                super().__init__([])
                self.urls = {
                    "tab-login": "https://auth.openai.com/log-in",
                    "tab-profile": "https://auth.openai.com/about-you",
                }
                self.window_handles = list(self.urls)
                self.current_window_handle = "tab-login"
                self.current_url = self.urls[self.current_window_handle]
                self.switch_to = Switch(self)

        driver = WindowDriver()
        self.flow.select_active_auth_window(driver, preferred_state="profile")

        self.assertEqual(driver.current_window_handle, "tab-profile")
        self.assertEqual(driver.current_url, "https://auth.openai.com/about-you")

    def test_wait_for_input_handles_delayed_rendering(self) -> None:
        field = _FakeOtpElement(inputmode="numeric", maxlength="6")

        class DelayedDriver(_FakeOtpDriver):
            def find_elements(self, by: object, selector: str) -> list[_FakeOtpElement]:
                self.find_calls += 1
                return [field] if self.find_calls >= 3 else []

        driver = DelayedDriver([])
        with patch.object(self.flow.time, "sleep", return_value=None):
            result = self.flow.wait_for_otp_input(driver, timeout=2)

        self.assertEqual(result, [field])
        self.assertGreaterEqual(driver.find_calls, 3)

    def test_clear_and_fill_single_input(self) -> None:
        field = _FakeOtpElement(value="123123", autocomplete="one-time-code")
        driver = _FakeOtpDriver([field])
        human = type("Human", (), {"delay": staticmethod(lambda _kind: None)})()

        self.flow.clear_otp_inputs(driver)
        self.flow.fill_otp(driver, "289772", human)

        self.assertEqual(field.value, "289772")
        self.assertGreaterEqual(len(field.sent), 1)

    def test_fill_supports_six_separate_digit_inputs(self) -> None:
        fields = [
            _FakeOtpElement(inputmode="numeric", maxlength="1", aria_label=f"Digit {index}")
            for index in range(6)
        ]
        driver = _FakeOtpDriver(fields)
        human = type("Human", (), {"delay": staticmethod(lambda _kind: None)})()

        self.flow.fill_otp(driver, "735687", human)

        self.assertEqual("".join(field.value for field in fields), "735687")

    def test_submit_probe_only_returns_safe_request_summary(self) -> None:
        driver = _FakeOtpDriver([_FakeOtpElement(inputmode="numeric")])
        driver.submit_probe.update({
            "submit_observed": True,
            "status": 422,
            "content_type": "application/json",
            "error_code": "invalid_code",
        })

        result = self.flow.install_otp_validate_probe(driver)
        self.assertTrue(result["submit_observed"])
        self.assertEqual(result["status"], 422)
        self.assertEqual(result["error_code"], "invalid_code")
        self.assertNotIn("735687", repr(result))
        self.assertNotIn("cookie", repr(result).lower())

    def test_continue_url_is_restricted_to_openai_hosts(self) -> None:
        self.assertEqual(
            self.flow._safe_continue_url("/authorize/continue?code=private"),
            "https://auth.openai.com/authorize/continue?code=private",
        )
        self.assertEqual(self.flow._safe_continue_url("https://example.test/callback"), "")
        self.assertEqual(self.flow._safe_continue_url("javascript:alert(1)"), "")

    def test_wait_after_submit_reports_japanese_invalid_code(self) -> None:
        driver = _FakeOtpDriver(
            [_FakeOtpElement(inputmode="numeric")],
            body="認証コードが正しくありません。もう一度お試しください。",
        )
        logs: list[tuple[str, str]] = []
        with patch.object(self.flow.time, "sleep", return_value=None):
            with self.assertRaises(Exception) as raised:
                self.flow.wait_after_otp_submit(
                    driver,
                    timeout=3,
                    log=lambda message, level="info": logs.append((level, message)),
                )
        self.assertEqual(getattr(raised.exception, "error_code", ""), "free_email_otp_invalid")
        self.assertTrue(any("验证码" in message or "OTP" in message for _level, message in logs))
        self.assertNotIn("289772", repr(logs))

    def test_wait_after_submit_accepts_transition_to_home(self) -> None:
        driver = _FakeOtpDriver([], body="")
        driver.current_url = "https://chatgpt.com/"
        with patch.object(self.flow.time, "sleep", return_value=None):
            state = self.flow.wait_after_otp_submit(driver, timeout=3)
        self.assertEqual(state, "home")

    def test_validate_http_422_is_attributed_to_otp_node(self) -> None:
        class ValidateDriver(_FakeOtpDriver):
            def execute_script(self, script: str, *args: object) -> object:
                if "__gptphone_email_otp_validate__" in script and "filter" in script:
                    return [{"status": 422, "contentType": "application/json", "errorCode": "invalid_code"}]
                return super().execute_script(script, *args)

        driver = ValidateDriver([_FakeOtpElement(inputmode="numeric")])
        with patch.object(self.flow.time, "sleep", return_value=None):
            with self.assertRaises(Exception) as raised:
                self.flow.wait_after_otp_submit(driver, timeout=2)
        self.assertEqual(getattr(raised.exception, "error_code", ""), "free_email_otp_invalid")
        self.assertEqual(getattr(raised.exception, "provider_status", None), 422)

    def test_terminal_provider_code_is_preserved_without_retry(self) -> None:
        class DeactivatedDriver(_FakeOtpDriver):
            def execute_script(self, script: str, *args: object) -> object:
                if "__gptphone_email_otp_validate__" in script and "filter" in script:
                    return [{
                        "status": 403,
                        "contentType": "application/json",
                        "errorCode": "account_deactivated",
                    }]
                return super().execute_script(script, *args)

        driver = DeactivatedDriver([_FakeOtpElement(inputmode="numeric")])
        with patch.object(self.flow.time, "sleep", return_value=None):
            with self.assertRaises(FreeRegisterError) as raised:
                self.flow.wait_after_otp_submit(driver, timeout=2)
        error = raised.exception
        self.assertEqual(error.error_code, "free_email_otp_account_deactivated")
        self.assertEqual(error.provider_code, "account_deactivated")
        self.assertFalse(error.retryable)
        self.assertIn("account_deactivated", str(error))

    def test_validate_http_503_is_retryable_and_keeps_safe_status(self) -> None:
        class ValidateDriver(_FakeOtpDriver):
            def execute_script(self, script: str, *args: object) -> object:
                if "__gptphone_email_otp_validate__" in script and "filter" in script:
                    return [{"status": 503, "contentType": "application/json", "errorCode": "upstream_unavailable"}]
                return super().execute_script(script, *args)

        driver = ValidateDriver([_FakeOtpElement(inputmode="numeric")])
        with patch.object(self.flow.time, "sleep", return_value=None):
            with self.assertRaises(Exception) as raised:
                self.flow.wait_after_otp_submit(driver, timeout=2)
        self.assertEqual(getattr(raised.exception, "error_code", ""), "free_email_otp_validate_failed")
        self.assertTrue(getattr(raised.exception, "retryable", False))
        self.assertEqual(getattr(raised.exception, "provider_status", None), 503)

    def test_numeric_provider_code_is_not_exposed_as_an_error_code(self) -> None:
        class NumericCodeDriver(_FakeOtpDriver):
            def execute_script(self, script: str, *args: object) -> object:
                if "__gptphone_email_otp_validate__" in script and "return {" in script:
                    return {
                        "hooked": True,
                        "submit_observed": True,
                        "rows": [{"status": 422, "contentType": "application/json", "errorCode": "735687"}],
                    }
                return super().execute_script(script, *args)

        result = self.flow.read_otp_validate_probe(NumericCodeDriver([]))
        self.assertEqual(result.get("error_code", ""), "")
        self.assertNotIn("735687", repr(result))

    def test_stalled_otp_page_has_submit_not_observed_node(self) -> None:
        driver = _FakeOtpDriver([_FakeOtpElement(inputmode="numeric")])
        with patch.object(self.flow.time, "sleep", return_value=None):
            with self.assertRaises(Exception) as raised:
                self.flow.wait_after_otp_submit(driver, timeout=1)
        self.assertEqual(getattr(raised.exception, "error_code", ""), "free_email_otp_submit_not_observed")

    def test_wait_for_input_stops_on_security_page(self) -> None:
        driver = _FakeOtpDriver([], body="Verify you are human")
        with patch.object(self.flow.time, "sleep", return_value=None):
            with self.assertRaises(Exception) as raised:
                self.flow.wait_for_otp_input(driver, timeout=2)
        self.assertEqual(getattr(raised.exception, "error_code", ""), "free_roxy_security_challenge")

    def test_attempt_limit_is_hard_capped_at_three(self) -> None:
        submitted: list[str] = []
        restarts: list[int] = []

        def wait_code(attempt: int) -> str:
            return f"{attempt}{attempt}{attempt}{attempt}{attempt}{attempt}"

        def submit_code(code: str, _attempt: int) -> str:
            submitted.append(code)
            raise FreeRegisterError(
                "free_email_otp_validate", "验证 Free 邮箱验证码",
                "验证码被拒绝", error_code="free_email_otp_invalid",
            )

        def restart(attempt: int) -> str:
            restarts.append(attempt)
            return "otp"

        with self.assertRaises(FreeRegisterError) as raised:
            self.flow.run_otp_attempts(
                wait_code=wait_code,
                submit_code=submit_code,
                restart_flow=restart,
                max_attempts=5,
            )
        self.assertEqual(getattr(raised.exception, "error_code", ""), "free_email_otp_invalid")
        self.assertEqual(len(submitted), 3)
        self.assertEqual(restarts, [2, 3])

    def test_attempt_orchestrator_reopens_and_never_reuses_submitted_code(self) -> None:
        codes = iter(["111111", "111111", "222222"])
        submitted: list[str] = []
        restarted: list[int] = []

        def wait_code(_attempt: int) -> str:
            return next(codes)

        def submit_code(code: str, _attempt: int) -> str:
            submitted.append(code)
            if len(submitted) == 1:
                raise FreeRegisterError(
                    "free_email_otp_validate", "验证 Free 邮箱验证码",
                    "验证码被认证接口拒绝", error_code="free_email_otp_invalid",
                )
            return "home"

        def restart(attempt: int) -> str:
            restarted.append(attempt)
            return "otp"

        state = self.flow.run_otp_attempts(
            wait_code=wait_code,
            submit_code=submit_code,
            restart_flow=restart,
            max_attempts=3,
        )
        self.assertEqual(state, "home")
        self.assertEqual(submitted, ["111111", "222222"])
        self.assertEqual(restarted, [2, 3])

    def test_pre_submit_failure_reloads_profile_and_reuses_code(self) -> None:
        submitted: list[str] = []
        reloaded: list[int] = []

        def wait_code(_attempt: int) -> str:
            return "333333"

        def submit_code(code: str, attempt: int) -> str:
            submitted.append(code)
            if len(submitted) == 1:
                raise FreeRegisterError(
                    "free_email_otp_validate", "验证 Free 邮箱验证码",
                    "控件未触发提交", error_code="free_email_otp_submit_not_observed",
                )
            return "home"

        def reload(attempt: int) -> str:
            reloaded.append(attempt)
            return "otp"

        state = self.flow.run_otp_attempts(
            wait_code=wait_code, submit_code=submit_code,
            restart_flow=lambda _attempt: "otp", reload_flow=reload,
        )
        self.assertEqual(state, "home")
        self.assertEqual(submitted, ["333333", "333333"])
        self.assertEqual(reloaded, [1])

    def test_pre_submit_reload_is_limited_to_one_per_task(self) -> None:
        submitted: list[str] = []
        reloaded: list[int] = []

        def submit_code(code: str, _attempt: int) -> str:
            submitted.append(code)
            raise FreeRegisterError(
                "free_email_otp_validate", "验证 Free 邮箱验证码",
                "验证码控件仍未触发提交", error_code="free_email_otp_input_missing",
            )

        def reload(attempt: int) -> str:
            reloaded.append(attempt)
            return "otp"

        with self.assertRaises(FreeRegisterError):
            self.flow.run_otp_attempts(
                wait_code=lambda _attempt: "444444",
                submit_code=submit_code,
                restart_flow=lambda _attempt: "otp",
                reload_flow=reload,
                max_attempts=3,
            )

        self.assertEqual(reloaded, [1])
        self.assertEqual(submitted, ["444444", "444444", "444444"])


if __name__ == "__main__":
    unittest.main()
