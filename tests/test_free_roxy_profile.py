from __future__ import annotations

from unittest.mock import patch
import unittest

from mac_overrides import free_roxy_profile


class _Field:
    def __init__(self) -> None:
        self.value = ""

    def clear(self) -> None:
        self.value = ""

    def send_keys(self, value: str) -> None:
        self.value += str(value)


class _Driver:
    current_url = "https://auth.openai.com/about-you"


class _Human:
    actions = False

    @staticmethod
    def delay(_kind: str) -> None:
        return None


class FreeRoxyProfileTests(unittest.TestCase):
    def test_profile_accepts_first_and_last_name_fields_when_full_name_is_absent(self):
        first, last = _Field(), _Field()
        states = iter(("profile", "home"))

        def find(_driver, selectors):
            joined = " ".join(selectors)
            if "firstName" in joined or "first_name" in joined:
                return first
            if "lastName" in joined or "last_name" in joined:
                return last
            return None

        with (
            patch.object(free_roxy_profile, "classify_page", side_effect=lambda _driver: next(states)),
            patch.object(free_roxy_profile, "_find_first", side_effect=find),
            patch.object(free_roxy_profile, "_set_birthday", return_value="react_select"),
            patch.object(free_roxy_profile, "_accept_consents", return_value=1),
            patch.object(free_roxy_profile, "_submit", return_value=True),
            patch.object(free_roxy_profile.time, "sleep"),
        ):
            result = free_roxy_profile.complete_profile_page(
                _Driver(), _Human(), "Example User", "1990-01-02", timeout=5,
            )

        self.assertTrue(result)
        self.assertEqual(first.value, "Example")
        self.assertEqual(last.value, "User")

    def test_profile_reselects_active_auth_window_before_each_poll(self):
        selected = []
        states = iter(("profile", "home"))

        with (
            patch.object(free_roxy_profile, "classify_page", side_effect=lambda _driver: next(states)),
            patch.object(free_roxy_profile, "_find_first", return_value=_Field()),
            patch.object(free_roxy_profile, "_set_birthday", return_value="age"),
            patch.object(free_roxy_profile, "_accept_consents", return_value=0),
            patch.object(free_roxy_profile, "_submit", return_value=True),
            patch.object(free_roxy_profile.time, "sleep"),
        ):
            result = free_roxy_profile.complete_profile_page(
                _Driver(),
                _Human(),
                "Example User",
                "1990-01-02",
                timeout=5,
                select_auth_window=lambda driver, log=None: selected.append((driver, log)),
            )

        self.assertTrue(result)
        self.assertEqual(len(selected), 2)


if __name__ == "__main__":
    unittest.main()
