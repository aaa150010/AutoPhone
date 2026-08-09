from __future__ import annotations

import hashlib
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

from mac_overrides.chatgpt_totp import (
    build_chatgpt_totp_patches,
    mailbox_credential_identity,
)
from mac_overrides.mailbox_admin import (
    MailboxAdminService,
    is_importable_mailbox_row,
    mailbox_url_from_row,
    masked_source_row,
    parse_mailbox_url_totp_row,
    parse_oauth_mailbox_row,
    password_from_row,
    redact_mailbox_credentials,
    row_id_from_source,
    totp_secret_from_row,
)
from mac_overrides.mailbox_password_url_rows import parse_mailbox_password_url_row
from mac_overrides.mailbox_row_formats import row_secrets


EMAIL = "user@example.test"
PASSWORD = "CaseSensitive123"
MAILBOX_URL = (
    "https://mail.example.test/latest?"
    "email=user%40example.test&auth_code=private-auth"
)


class FakeStore:
    def __init__(self, root: Path) -> None:
        self.data_dir = root

    def load(self):
        return {
            "pool_path": "pool.txt",
            "state_path": "state.json",
            "results_dir": "results",
        }


class PoolEntry:
    def __init__(self, **kwargs) -> None:
        self.__dict__.update(kwargs)


def build_patches():
    return build_chatgpt_totp_patches(
        runtime_module=SimpleNamespace(PoolEntry=PoolEntry),
        codex_oauth_chain=SimpleNamespace(),
        original_entries_unlocked=lambda _pool: ([], ["line 1: unsupported row"]),
        original_outlook_otp_provider=lambda *args, **kwargs: None,
        original_account_label=lambda entry: entry.email,
        original_verify_password=lambda *args: {},
        original_send_mfa_otp=lambda *args: {},
        original_verify_mfa_otp=lambda *args: {},
        parse_oauth_mailbox_row=parse_oauth_mailbox_row,
    )


class MailboxPasswordUrlRowTests(unittest.TestCase):
    def test_password_first_and_labeled_url_first_normalize_to_the_same_row(self):
        password_first = f"{EMAIL}----{PASSWORD}----{MAILBOX_URL}"
        url_first = f"{EMAIL}----{MAILBOX_URL}----密码：{PASSWORD}"

        parsed_password_first = parse_mailbox_password_url_row(password_first)
        parsed_url_first = parse_mailbox_password_url_row(url_first)

        self.assertIsNotNone(parsed_password_first)
        self.assertEqual(parsed_password_first, parsed_url_first)
        self.assertEqual(parsed_password_first.canonical(), password_first)
        for row in (password_first, url_first):
            self.assertTrue(is_importable_mailbox_row(row))
            self.assertEqual(password_from_row(row), PASSWORD)
            self.assertEqual(mailbox_url_from_row(row), MAILBOX_URL)
            self.assertEqual(totp_secret_from_row(row), "")
            self.assertEqual(
                masked_source_row(row),
                f"{EMAIL}----********----********",
            )

    def test_url_first_requires_password_label_and_does_not_steal_url_totp(self):
        unlabeled = f"{EMAIL}----{MAILBOX_URL}----{PASSWORD}"
        url_totp = f"{EMAIL}----{MAILBOX_URL}----JBSWY3DPEHPK3PXP"

        self.assertIsNone(parse_mailbox_password_url_row(unlabeled))
        self.assertFalse(is_importable_mailbox_row(unlabeled))
        self.assertEqual(password_from_row(unlabeled), "")
        self.assertIsNone(parse_mailbox_password_url_row(url_totp))
        self.assertIsNotNone(parse_mailbox_url_totp_row(url_totp))
        self.assertIsNone(parse_mailbox_password_url_row(f"{EMAIL}----{PASSWORD}----ftp://invalid"))
        self.assertIsNone(parse_mailbox_password_url_row(f"{EMAIL}----{MAILBOX_URL}----密码："))

    def test_password_separator_is_not_misclassified_as_oauth(self):
        password = "part-one----part-two"
        row = f"{EMAIL}----{password}----{MAILBOX_URL}"

        parsed = parse_mailbox_password_url_row(row)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.password, password)
        self.assertTrue(is_importable_mailbox_row(row))
        self.assertEqual(password_from_row(row), password)
        self.assertEqual(masked_source_row(row), f"{EMAIL}----********----********")

        class PoolEntry:
            def __init__(self, **kwargs):
                self.__dict__.update(kwargs)

        with tempfile.TemporaryDirectory() as temp_dir:
            pool_path = Path(temp_dir) / "pool.txt"
            pool_path.write_text(row + "\n", encoding="utf-8")
            patches = build_chatgpt_totp_patches(
                runtime_module=SimpleNamespace(PoolEntry=PoolEntry),
                codex_oauth_chain=SimpleNamespace(),
                original_entries_unlocked=lambda _pool: ([], ["line 1: unsupported row"]),
                original_outlook_otp_provider=lambda *args, **kwargs: None,
                original_account_label=lambda entry: entry.email,
                original_verify_password=lambda *args: {},
                original_send_mfa_otp=lambda *args: {},
                original_verify_mfa_otp=lambda *args: {},
                parse_oauth_mailbox_row=parse_oauth_mailbox_row,
            )
            entries, errors = patches.entries_unlocked(SimpleNamespace(pool_path=pool_path))

        self.assertEqual(errors, [])
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].mailbox_type, "url")
        self.assertEqual(entries[0].password, password)
        self.assertEqual(entries[0].mailbox_url, MAILBOX_URL)

    def test_unrecognized_composite_rows_still_redact_each_credential_fragment(self):
        row = f"{EMAIL}----{MAILBOX_URL}----{PASSWORD}"
        diagnostic = f"row={EMAIL} url={MAILBOX_URL} password={PASSWORD}"
        redacted = redact_mailbox_credentials(diagnostic, row_secrets(row))
        self.assertNotIn(EMAIL, redacted)
        self.assertNotIn(MAILBOX_URL, redacted)
        self.assertNotIn(PASSWORD, redacted)

    def test_combined_identity_matches_the_existing_plain_password_account(self):
        combined = f"{EMAIL}----{PASSWORD}----{MAILBOX_URL}"
        plain = f"{EMAIL}----{PASSWORD}"

        self.assertEqual(
            mailbox_credential_identity(combined, parse_oauth_mailbox_row),
            mailbox_credential_identity(plain, parse_oauth_mailbox_row),
        )

    def test_all_password_and_url_fragments_are_redacted(self):
        row = f"{EMAIL}----{PASSWORD}----{MAILBOX_URL}"
        diagnostic = f"failed {EMAIL} {PASSWORD} {MAILBOX_URL} private-auth"

        redacted = redact_mailbox_credentials(diagnostic, row_secrets(row))

        for secret in (EMAIL, PASSWORD, MAILBOX_URL, "private-auth"):
            self.assertNotIn(secret, redacted)

    def test_runtime_entry_uses_url_otp_while_retaining_login_password(self):
        row = f"{EMAIL}----{PASSWORD}----{MAILBOX_URL}"
        with tempfile.TemporaryDirectory() as temp_dir:
            pool_path = Path(temp_dir) / "pool.txt"
            pool_path.write_text(f"{row}\n", encoding="utf-8")

            entries, errors = build_patches().entries_unlocked(
                SimpleNamespace(pool_path=pool_path)
            )

        self.assertEqual(errors, [])
        self.assertEqual(len(entries), 1)
        entry = entries[0]
        self.assertEqual(entry.email, EMAIL)
        self.assertEqual(entry.password, PASSWORD)
        self.assertEqual(entry.mailbox_url, MAILBOX_URL)
        self.assertEqual(entry.mailbox_type, "url")
        self.assertEqual(entry.source_row, row)
        expected_identity = mailbox_credential_identity(row, parse_oauth_mailbox_row)[1]
        self.assertEqual(
            entry.key,
            hashlib.sha256(f"{EMAIL}\x1f{expected_identity}".encode()).hexdigest(),
        )

    def test_mailbox_admin_lists_and_reveals_both_credentials_and_uses_url_reader(self):
        row = f"{EMAIL}----{PASSWORD}----{MAILBOX_URL}"
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "pool.txt").write_text(f"{row}\n", encoding="utf-8")
            captured_urls = []
            imap_calls = []

            class Reader:
                def __init__(self, mailbox_url, **_kwargs) -> None:
                    captured_urls.append(mailbox_url)

                def latest_code(self, **_kwargs):
                    return SimpleNamespace(code="123456")

            service = MailboxAdminService(
                FakeStore(root),
                validate_pool=lambda _config: {"ok": True},
                imap_poller_factory=lambda *args, **kwargs: imap_calls.append((args, kwargs)),
                mailbox_url_reader_factory=Reader,
            )

            listed = service.list_mailboxes()["rows"][0]
            password = service.reveal_password(row_id_from_source(row), 1)
            mailbox_url = service.reveal_mailbox_url(row_id_from_source(row), 1)
            latest = service.latest_code({"line_no": 1})

        self.assertEqual(listed["password"], "********")
        self.assertTrue(listed["has_mailbox_url"])
        self.assertFalse(listed["has_totp"])
        self.assertNotIn(PASSWORD, listed["source_row"])
        self.assertNotIn(MAILBOX_URL, listed["source_row"])
        self.assertEqual(password, {"ok": True, "password": PASSWORD})
        self.assertEqual(mailbox_url, {"ok": True, "mailbox_url": MAILBOX_URL})
        self.assertEqual(captured_urls, [MAILBOX_URL])
        self.assertEqual(imap_calls, [])
        self.assertEqual(latest["code"], "123456")


if __name__ == "__main__":
    unittest.main()
