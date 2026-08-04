from __future__ import annotations

from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

from mac_overrides.chatgpt_totp import (
    build_chatgpt_totp_patches,
    masked_chatgpt_totp_row,
    parse_chatgpt_totp_row,
    totp_code,
)
from mac_overrides.mailbox_admin import parse_oauth_mailbox_row
from mac_overrides.mailbox_url_runtime import parse_mailbox_url_row


class ChatGptTotpTests(unittest.TestCase):
    def test_parses_and_masks_chatgpt_totp_rows(self):
        expected = ("user@example.com", "pa-ss:word", "JBSWY3DPEHPK3PXP")
        rows = (
            " User@Example.com--pa-ss:word--JBSW Y3DP EHPK3PXP ",
            "User@Example.com---pa-ss:word---JBSWY3DPEHPK3PXP",
            "User@Example.com----pa-ss:word----JBSWY3DPEHPK3PXP",
            "User@Example.com|pa-ss:word|JBSWY3DPEHPK3PXP",
            "User@Example.com\tpa-ss:word\tJBSWY3DPEHPK3PXP",
            "User@Example.com,pa-ss:word,JBSWY3DPEHPK3PXP",
            "User@Example.com;pa-ss:word;JBSWY3DPEHPK3PXP",
            "User@Example.com：pa-ss-word：JBSWY3DPEHPK3PXP",
        )
        for row in rows:
            with self.subTest(row=row):
                parsed = parse_chatgpt_totp_row(row)
                if "：" in row:
                    self.assertEqual(
                        parsed,
                        ("user@example.com", "pa-ss-word", "JBSWY3DPEHPK3PXP"),
                    )
                else:
                    self.assertEqual(parsed, expected)
        self.assertEqual(
            parse_chatgpt_totp_row(
                "User@Example.com----password----2FA: JBSW-Y3DP-EHPK-3PXP"
            ),
            ("user@example.com", "password", "JBSWY3DPEHPK3PXP"),
        )
        self.assertEqual(
            masked_chatgpt_totp_row(
                "User@Example.com--password--JBSWY3DPEHPK3PXP", "********"
            ),
            "user@example.com--********--********",
        )
        self.assertIsNone(parse_chatgpt_totp_row("not-an-email|password|ABCDEFGH"))
        self.assertIsNone(parse_chatgpt_totp_row("user@example.com|password"))
        self.assertIsNone(parse_chatgpt_totp_row("user@example.com|password|not-a-key"))
        self.assertIsNone(
            parse_chatgpt_totp_row(
                "user@example.com----password----client-id----refresh-token"
            )
        )

    def test_totp_matches_rfc_6238_sha1_vector(self):
        secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        self.assertEqual(totp_code(secret, now=59, digits=8), "94287082")

    def test_two_or_more_ascii_and_unicode_dashes_are_supported(self):
        delimiters = (
            "--",
            "---",
            "----",
            "――",
            "——",
            "––",
            "−−",
            "－－",
            "﹣﹣",
            "-—",
        )
        for delimiter in delimiters:
            row = f"User@Example.com{delimiter}pa-ss{delimiter}JBSWY3DPEHPK3PXP"
            with self.subTest(delimiter=delimiter):
                self.assertEqual(
                    parse_chatgpt_totp_row(row),
                    ("user@example.com", "pa-ss", "JBSWY3DPEHPK3PXP"),
                )
                self.assertEqual(
                    masked_chatgpt_totp_row(row, "********"),
                    delimiter.join(("user@example.com", "********", "********")),
                )
        self.assertIsNone(
            parse_chatgpt_totp_row("user@example.com-password-JBSWY3DPEHPK3PXP")
        )

    def test_password_may_contain_the_selected_delimiter(self):
        rows = (
            "user@example.com--pa--ss--JBSWY3DPEHPK3PXP",
            "user@example.com|pa|ss|JBSWY3DPEHPK3PXP",
            "user@example.com,pa,ss,JBSWY3DPEHPK3PXP",
            "user@example.com;pa;ss;JBSWY3DPEHPK3PXP",
            "user@example.com:pa:ss:JBSWY3DPEHPK3PXP",
            "user@example.com｜pa｜ss｜JBSWY3DPEHPK3PXP",
            "user@example.com，pa，ss，JBSWY3DPEHPK3PXP",
            "user@example.com；pa；ss；JBSWY3DPEHPK3PXP",
            "user@example.com：pa：ss：JBSWY3DPEHPK3PXP",
        )
        for row in rows:
            with self.subTest(row=row):
                parsed = parse_chatgpt_totp_row(row)
                self.assertIsNotNone(parsed)
                self.assertTrue(parsed[1].startswith("pa"))
                self.assertTrue(parsed[1].endswith("ss"))

    def test_oauth_shape_wins_even_when_oauth_fields_look_like_base32(self):
        self.assertIsNone(
            parse_chatgpt_totp_row(
                "user@example.com----password----JBSWY3DPEHPK3PXP----MZXW6YTBOI======"
            )
        )
        incomplete_rows = (
            "user@example.com--------client-id----JBSWY3DPEHPK3PXP",
            "user@example.com----password--------JBSWY3DPEHPK3PXP",
            "user@example.com----password----client-id----",
        )
        for row in incomplete_rows:
            with self.subTest(row=row):
                self.assertIsNone(parse_oauth_mailbox_row(row))
                self.assertIsNone(parse_chatgpt_totp_row(row))

    def test_mixed_pool_builds_the_correct_runtime_entry_type(self):
        class PoolEntry:
            def __init__(self, **kwargs):
                self.__dict__.update(kwargs)

        with tempfile.TemporaryDirectory() as temp_dir:
            pool_path = Path(temp_dir) / "pool.txt"
            pool_path.write_text(
                "dash@example.com----dash-pass----JBSWY3DPEHPK3PXP\n"
                "pipe@example.com|pipe-pass|JBSWY3DPEHPK3PXP\n"
                "oauth@example.com----oauth-pass----client-id----refresh-token\n",
                encoding="utf-8",
            )
            patches = build_chatgpt_totp_patches(
                runtime_module=SimpleNamespace(PoolEntry=PoolEntry),
                codex_oauth_chain=SimpleNamespace(),
                original_entries_unlocked=lambda _pool: (
                    [],
                    ["line 1: bad", "line 2: bad", "line 3: bad"],
                ),
                original_outlook_otp_provider=lambda *args, **kwargs: None,
                original_account_label=lambda entry: entry.email,
                original_verify_password=lambda *args: {},
                original_send_mfa_otp=lambda *args: {},
                original_verify_mfa_otp=lambda *args: {},
                parse_oauth_mailbox_row=parse_oauth_mailbox_row,
            )

            entries, errors = patches.entries_unlocked(SimpleNamespace(pool_path=pool_path))

        self.assertEqual(errors, [])
        self.assertEqual([entry.email for entry in entries], [
            "dash@example.com",
            "pipe@example.com",
            "oauth@example.com",
        ])
        self.assertEqual([entry.mailbox_type for entry in entries], [
            "outlook_password",
            "outlook_password",
            "outlook_oauth",
        ])
        self.assertEqual(entries[0].oauth_client_id, "chatgpt_totp")
        self.assertEqual(entries[2].oauth_client_id, "client-id")
        self.assertNotIn("oauth-pass", entries[2].source_row)
        self.assertNotIn("client-id", entries[2].source_row)
        self.assertNotIn("refresh-token", entries[2].source_row)

    def test_url_rows_with_dash_and_pipe_separators_build_masked_runtime_entries(self):
        class PoolEntry:
            def __init__(self, **kwargs):
                self.__dict__.update(kwargs)

        rows = (
            "dash@example.com---https://mail.example.test/messages/private-dash-token",
            "pipe@example.com|http://mail.example.test/messages/private-pipe-token",
            "wide@example.com｜https://mail.example.test/messages/private-wide-token",
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            pool_path = Path(temp_dir) / "pool.txt"
            pool_path.write_text("\n".join(rows) + "\n", encoding="utf-8")
            patches = build_chatgpt_totp_patches(
                runtime_module=SimpleNamespace(PoolEntry=PoolEntry),
                codex_oauth_chain=SimpleNamespace(),
                original_entries_unlocked=lambda _pool: (
                    [],
                    [f"line {index}: bad" for index in range(1, 4)],
                ),
                original_outlook_otp_provider=lambda *args, **kwargs: None,
                original_account_label=lambda entry: entry.email,
                original_verify_password=lambda *args: {},
                original_send_mfa_otp=lambda *args: {},
                original_verify_mfa_otp=lambda *args: {},
                parse_oauth_mailbox_row=parse_oauth_mailbox_row,
            )

            entries, errors = patches.entries_unlocked(SimpleNamespace(pool_path=pool_path))

        self.assertEqual(errors, [])
        self.assertEqual([entry.mailbox_type for entry in entries], ["url", "url", "url"])
        for row, entry in zip(rows, entries):
            parsed = parse_mailbox_url_row(row)
            self.assertIsNotNone(parsed)
            self.assertEqual(entry.mailbox_url, parsed.mailbox_url)
            self.assertNotIn(parsed.mailbox_url, entry.source_row)
            self.assertIn("***", entry.source_row)


if __name__ == "__main__":
    unittest.main()
