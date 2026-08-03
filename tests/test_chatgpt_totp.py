from __future__ import annotations

import unittest

from mac_overrides.chatgpt_totp import (
    masked_chatgpt_totp_row,
    parse_chatgpt_totp_row,
    totp_code,
)


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


if __name__ == "__main__":
    unittest.main()
