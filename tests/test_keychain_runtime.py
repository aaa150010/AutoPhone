"""Targeted tests for the SecurityKeyProvider keychain decision paths."""

from __future__ import annotations

from types import SimpleNamespace
import unittest

from mac_overrides.keychain_runtime import (
    CheckpointError,
    KeychainUnavailable,
    SecurityKeyProvider,
    _b64,
)


def runner_with_find(find_result, *, add_returncode: int = 0):
    """Build a fake runner whose find returns ``find_result`` verbatim."""
    calls = []

    def runner(argv, **kwargs):
        calls.append((list(argv), kwargs))
        if "find-generic-password" in argv:
            return find_result
        return SimpleNamespace(returncode=add_returncode, stdout="")

    return runner, calls


class SecurityKeyProviderGetOrCreateTests(unittest.TestCase):
    def test_returncode_zero_with_valid_key_returns_value_without_add(self):
        key = bytes(range(32))
        runner, calls = runner_with_find(
            SimpleNamespace(returncode=0, stdout=_b64(key), stderr="")
        )

        result = SecurityKeyProvider(runner=runner).get_or_create()

        self.assertEqual(result, key)
        self.assertEqual(len(calls), 1)
        self.assertIn("find-generic-password", calls[0][0])

    def test_returncode_zero_with_corrupt_base64_raises_without_add(self):
        runner, calls = runner_with_find(
            SimpleNamespace(returncode=0, stdout="!!!not-base64!!!", stderr="security: secrets")
        )

        with self.assertRaisesRegex(CheckpointError, "无法解析"):
            SecurityKeyProvider(runner=runner).get_or_create()
        self.assertEqual([argv for argv, _kwargs in calls if "add-generic-password" in argv], [])

    def test_returncode_zero_with_wrong_length_raises_without_add(self):
        runner, _calls = runner_with_find(
            SimpleNamespace(returncode=0, stdout=_b64(b"short"), stderr="")
        )

        with self.assertRaisesRegex(CheckpointError, "无法解析"):
            SecurityKeyProvider(runner=runner).get_or_create()

    def test_returncode_44_creates_key_once(self):
        key_holder = {}

        def runner(argv, **kwargs):
            if "find-generic-password" in argv:
                return SimpleNamespace(returncode=44, stdout="", stderr="")
            input_text = kwargs.get("input") or ""
            key_holder["input"] = input_text
            return SimpleNamespace(returncode=0, stdout="")

        result = SecurityKeyProvider(runner=runner).get_or_create()

        self.assertEqual(len(result), 32)
        self.assertEqual(key_holder["input"], f"{_b64(result)}\n{_b64(result)}\n")

    def test_returncode_45_locked_keychain_raises_without_overwrite(self):
        runner, calls = runner_with_find(
            SimpleNamespace(
                returncode=45,
                stdout="",
                stderr="security: SecKeychainSearchCopyNext: User interaction is not allowed.",
            )
        )

        with self.assertRaisesRegex(KeychainUnavailable, "returncode=45"):
            SecurityKeyProvider(runner=runner).get_or_create()
        self.assertEqual(
            [argv for argv, _kwargs in calls if "add-generic-password" in argv],
            [],
        )

    def test_failure_message_carries_only_digest_not_stderr_content(self):
        secret_detail = "security: keychain 'login' contains password-data"
        runner, _calls = runner_with_find(
            SimpleNamespace(returncode=51, stdout="", stderr=secret_detail)
        )

        with self.assertRaises(KeychainUnavailable) as raised:
            SecurityKeyProvider(runner=runner).get_or_create()

        message = str(raised.exception)
        self.assertNotIn(secret_detail, message)
        self.assertIn("sha256:", message)


if __name__ == "__main__":
    unittest.main()
