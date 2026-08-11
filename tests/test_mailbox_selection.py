from __future__ import annotations

import unittest

from mac_overrides.mailbox_row_formats import row_id_from_source
from mac_overrides.mailbox_selection import resolve_source_rows


class MailboxSelectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.lines = [
            "account@example.test---password---JBSWY3DPEHPK3PXP",
            "url@example.test---https://mail.example.test/inbox/AbCd",
        ]

    def test_resolves_valid_bindings_without_changing_source(self):
        result = resolve_source_rows({"rows": [
            {"row_id": row_id_from_source(self.lines[1]), "line_no": 2},
            {"row_id": row_id_from_source(self.lines[0]), "line_no": 1},
        ]}, self.lines, row_id_from_source)

        self.assertTrue(result["ok"])
        self.assertEqual([item["source_row"] for item in result["rows"]], [self.lines[1], self.lines[0]])

    def test_rejects_duplicate_invalid_and_stale_bindings_as_a_whole(self):
        binding = {"row_id": row_id_from_source(self.lines[0]), "line_no": 1}
        cases = (
            ({"rows": []}, "mailbox_rows_required"),
            ({"rows": [binding, binding]}, "mailbox_rows_invalid"),
            ({"rows": [{"row_id": binding["row_id"], "line_no": 2}]}, "mailbox_rows_stale"),
            ({"rows": [{"row_id": binding["row_id"], "line_no": 99}]}, "mailbox_rows_stale"),
        )
        for payload, code in cases:
            with self.subTest(code=code):
                result = resolve_source_rows(payload, self.lines, row_id_from_source)
                self.assertFalse(result["ok"])
                self.assertEqual(result["code"], code)
                self.assertNotIn("password", str(result))


if __name__ == "__main__":
    unittest.main()
