from __future__ import annotations

import unittest

from mac_overrides.chatgpt_totp import parse_chatgpt_totp_row, totp_code


class ChatGptTotpTests(unittest.TestCase):
    def test_parses_and_masks_chatgpt_totp_rows(self):
        parsed = parse_chatgpt_totp_row(" User@Example.com | password | ABCD EFGH ")
        self.assertEqual(parsed, ("user@example.com", "password", "ABCDEFGH"))
        self.assertIsNone(parse_chatgpt_totp_row("not-an-email|password|ABCDEFGH"))
        self.assertIsNone(parse_chatgpt_totp_row("user@example.com|password"))

    def test_totp_matches_rfc_6238_sha1_vector(self):
        secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        self.assertEqual(totp_code(secret, now=59, digits=8), "94287082")


if __name__ == "__main__":
    unittest.main()
