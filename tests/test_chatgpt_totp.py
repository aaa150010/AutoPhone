from __future__ import annotations

from pathlib import Path
import hashlib
import json
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from mac_overrides.chatgpt_totp import (
    build_chatgpt_totp_patches,
    masked_chatgpt_totp_row,
    parse_chatgpt_totp_row,
    parse_mailbox_url_totp_row,
    pending_transport_totp_payload,
    refresh_transport_totp_payload,
    totp_code,
)
from mac_overrides.mailbox_admin import parse_oauth_mailbox_row, parse_plain_password_mailbox_row
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

    def test_url_totp_requires_exactly_three_valid_segments(self):
        valid = (
            "user@example.com----https://mail.example.test/latest?mail=user%40example.com----"
            "JBSWY3DPEHPK3PXP"
        )
        self.assertEqual(
            parse_mailbox_url_totp_row(valid),
            (
                "user@example.com",
                "https://mail.example.test/latest?mail=user%40example.com",
                "JBSWY3DPEHPK3PXP",
            ),
        )

        oauth = (
            "user@example.com----https://mail.example.test/password----"
            "JBSWY3DPEHPK3PXP----refresh-token"
        )
        self.assertIsNotNone(parse_oauth_mailbox_row(oauth))
        self.assertIsNone(parse_mailbox_url_totp_row(oauth))
        for invalid in (
            valid + "----extra",
            "user@example.com----https:///missing-host----JBSWY3DPEHPK3PXP",
            "user@example.com----https://mail.example.test:99999/inbox----JBSWY3DPEHPK3PXP",
            "user@example.com----https://mail.example.test/has space----JBSWY3DPEHPK3PXP",
            "user@example.com----https://mail.example.test/inbox----INVALID018",
        ):
            with self.subTest(invalid=invalid):
                self.assertIsNone(parse_mailbox_url_totp_row(invalid))

    def test_code_endpoint_url_totp_rows_build_url_entries_without_exposing_secret(self):
        secret = "JBSWY3DPEHPK3PXP"
        row = (
            "dejon_exltx-split-test@atheist.com----"
            "http://43.131.226.181/code/test-token----"
            f"{secret}"
        )
        self.assertEqual(
            parse_mailbox_url_totp_row(row),
            (
                "dejon_exltx-split-test@atheist.com",
                "http://43.131.226.181/code/test-token",
                secret,
            ),
        )
        self.assertEqual(totp_code(secret, now=59), "996554")

        class PoolEntry:
            def __init__(self, **kwargs):
                self.__dict__.update(kwargs)

        with tempfile.TemporaryDirectory() as temp_dir:
            pool_path = Path(temp_dir) / "pool.txt"
            pool_path.write_text(row + "\n", encoding="utf-8")
            patches = build_chatgpt_totp_patches(
                runtime_module=SimpleNamespace(PoolEntry=PoolEntry),
                codex_oauth_chain=SimpleNamespace(),
                original_entries_unlocked=lambda _pool: ([], ["line 1: bad"]),
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
        entry = entries[0]
        self.assertEqual(entry.email, "dejon_exltx-split-test@atheist.com")
        self.assertEqual(entry.mailbox_type, "url")
        self.assertEqual(entry.mailbox_url, "http://43.131.226.181/code/test-token")
        self.assertEqual(entry.oauth_client_id, "chatgpt_totp")
        self.assertEqual(entry.oauth_refresh_token, secret)

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
        self.assertEqual(
            entries[2].source_row,
            "oauth@example.com----oauth-pass----client-id----refresh-token",
        )

    def test_plain_password_pool_rows_build_non_totp_password_entries(self):
        class PoolEntry:
            def __init__(self, **kwargs):
                self.__dict__.update(kwargs)

        rows = (
            "plain@example.com--plain-pass",
            "pipeplain@example.com|pipe-pass",
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            pool_path = Path(temp_dir) / "pool.txt"
            pool_path.write_text("\n".join(rows) + "\n", encoding="utf-8")
            patches = build_chatgpt_totp_patches(
                runtime_module=SimpleNamespace(PoolEntry=PoolEntry),
                codex_oauth_chain=SimpleNamespace(),
                original_entries_unlocked=lambda _pool: (
                    [],
                    ["line 1: bad", "line 2: bad"],
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
        self.assertEqual([entry.email for entry in entries], ["plain@example.com", "pipeplain@example.com"])
        self.assertEqual([entry.password for entry in entries], ["plain-pass", "pipe-pass"])
        self.assertEqual([entry.mailbox_type for entry in entries], ["outlook_password", "outlook_password"])
        self.assertEqual([entry.oauth_client_id for entry in entries], ["", ""])
        self.assertEqual([entry.oauth_refresh_token for entry in entries], ["", ""])
        self.assertEqual(entries[0].source_row, rows[0])
        self.assertEqual(entries[1].source_row, rows[1])
        self.assertEqual(parse_plain_password_mailbox_row(rows[0]), ("plain@example.com", "plain-pass", "--"))

    def test_plain_password_formats_share_one_stable_identity(self):
        class PoolEntry:
            def __init__(self, **kwargs):
                self.__dict__.update(kwargs)

        rows = (
            "same@example.com----same-pass",
            "same@example.com--same-pass",
            "same@example.com|same-pass",
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

        expected_key = hashlib.sha256(
            b"same@example.com\x1foutlook::same-pass"
        ).hexdigest()
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].key, expected_key)
        self.assertEqual(entries[0].source_row, rows[0])
        self.assertEqual(errors, [
            "line 2: duplicate mailbox row",
            "line 3: duplicate mailbox row",
        ])

    def test_plain_password_legacy_state_key_is_still_honored(self):
        class PoolEntry:
            def __init__(self, **kwargs):
                self.__dict__.update(kwargs)

        row = "legacy@example.com|legacy-pass"
        legacy_key = hashlib.sha256(f"legacy@example.com\n{row}".encode()).hexdigest()
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            pool_path = root / "pool.txt"
            state_path = root / "state.json"
            pool_path.write_text(row + "\n", encoding="utf-8")
            state_path.write_text(
                json.dumps({"items": {legacy_key: {"status": "consumed"}}}),
                encoding="utf-8",
            )
            patches = build_chatgpt_totp_patches(
                runtime_module=SimpleNamespace(PoolEntry=PoolEntry),
                codex_oauth_chain=SimpleNamespace(),
                original_entries_unlocked=lambda _pool: ([], ["line 1: bad"]),
                original_outlook_otp_provider=lambda *args, **kwargs: None,
                original_account_label=lambda entry: entry.email,
                original_verify_password=lambda *args: {},
                original_send_mfa_otp=lambda *args: {},
                original_verify_mfa_otp=lambda *args: {},
                parse_oauth_mailbox_row=parse_oauth_mailbox_row,
            )

            entries, errors = patches.entries_unlocked(
                SimpleNamespace(pool_path=pool_path, state_path=state_path)
            )
            migrated = json.loads(state_path.read_text(encoding="utf-8"))["items"]

        canonical_key = hashlib.sha256(
            b"legacy@example.com\x1foutlook::legacy-pass"
        ).hexdigest()
        self.assertEqual(errors, [])
        self.assertEqual(entries[0].key, canonical_key)
        self.assertEqual(set(migrated), {canonical_key})
        self.assertEqual(migrated[canonical_key]["status"], "consumed")

    def test_plain_password_state_merge_never_downgrades_terminal_to_available(self):
        class PoolEntry:
            def __init__(self, **kwargs):
                self.__dict__.update(kwargs)

        class MailboxPoolModule:
            @staticmethod
            def _entry_key(email, identity):
                return hashlib.sha256(
                    f"{email.lower()}\x1f{identity}".encode("utf-8", "ignore")
                ).hexdigest()

        row = "Merge@Example.com----CasePass"
        canonical = MailboxPoolModule._entry_key(
            "merge@example.com", "outlook::CasePass"
        )
        legacy = MailboxPoolModule._entry_key("merge@example.com", row)
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            pool_path = root / "pool.txt"
            state_path = root / "state.json"
            pool_path.write_text(row + "\n", encoding="utf-8")
            state_path.write_text(
                json.dumps({
                    "items": {
                        canonical: {
                            "email": "merge@example.com",
                            "line_no": 1,
                            "status": "available",
                            "updated_at": 200,
                        },
                        legacy: {
                            "email": "merge@example.com",
                            "line_no": 1,
                            "status": "consumed",
                            "updated_at": 100,
                            "history": [{"event": "consumed", "at": 100}],
                        },
                    }
                }),
                encoding="utf-8",
            )
            patches = build_chatgpt_totp_patches(
                runtime_module=SimpleNamespace(
                    PoolEntry=PoolEntry,
                    _mailbox_pool=MailboxPoolModule,
                ),
                codex_oauth_chain=SimpleNamespace(),
                original_entries_unlocked=lambda _pool: ([], ["line 1: bad"]),
                original_outlook_otp_provider=lambda *args, **kwargs: None,
                original_account_label=lambda entry: entry.email,
                original_verify_password=lambda *args: {},
                original_send_mfa_otp=lambda *args: {},
                original_verify_mfa_otp=lambda *args: {},
                parse_oauth_mailbox_row=parse_oauth_mailbox_row,
            )

            entries, errors = patches.entries_unlocked(
                SimpleNamespace(pool_path=pool_path, state_path=state_path)
            )
            migrated = json.loads(state_path.read_text(encoding="utf-8"))["items"]

        self.assertEqual(errors, [])
        self.assertEqual(entries[0].key, canonical)
        self.assertEqual(set(migrated), {canonical})
        self.assertEqual(migrated[canonical]["status"], "consumed")
        self.assertEqual(
            migrated[canonical]["history"],
            [{"event": "consumed", "at": 100}],
        )

    def test_plain_password_format_change_cannot_bypass_valid_legacy_lease(self):
        class PoolEntry:
            def __init__(self, **kwargs):
                self.__dict__.update(kwargs)

        class MailboxPoolModule:
            @staticmethod
            def _entry_key(email, identity):
                return hashlib.sha256(
                    f"{email.lower()}\x1f{identity}".encode("utf-8", "ignore")
                ).hexdigest()

        current_row = "lease@example.com|CasePass"
        previous_row = "LEASE@EXAMPLE.COM----CasePass"
        canonical = MailboxPoolModule._entry_key(
            "lease@example.com", "outlook::CasePass"
        )
        legacy = MailboxPoolModule._entry_key("lease@example.com", previous_row)
        lease_until = 4_102_444_800
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            pool_path = root / "pool.txt"
            state_path = root / "state.json"
            pool_path.write_text(current_row + "\n", encoding="utf-8")
            state_path.write_text(
                json.dumps({
                    "items": {
                        legacy: {
                            "email": "lease@example.com",
                            "line_no": 1,
                            "status": "leased",
                            "lease_until": lease_until,
                            "updated_at": 100,
                        }
                    }
                }),
                encoding="utf-8",
            )
            patches = build_chatgpt_totp_patches(
                runtime_module=SimpleNamespace(
                    PoolEntry=PoolEntry,
                    _mailbox_pool=MailboxPoolModule,
                ),
                codex_oauth_chain=SimpleNamespace(),
                original_entries_unlocked=lambda _pool: ([], ["line 1: bad"]),
                original_outlook_otp_provider=lambda *args, **kwargs: None,
                original_account_label=lambda entry: entry.email,
                original_verify_password=lambda *args: {},
                original_send_mfa_otp=lambda *args: {},
                original_verify_mfa_otp=lambda *args: {},
                parse_oauth_mailbox_row=parse_oauth_mailbox_row,
            )

            entries, errors = patches.entries_unlocked(
                SimpleNamespace(pool_path=pool_path, state_path=state_path)
            )
            migrated = json.loads(state_path.read_text(encoding="utf-8"))["items"]

        self.assertEqual(errors, [])
        self.assertEqual(entries[0].key, canonical)
        self.assertEqual(set(migrated), {canonical})
        self.assertEqual(migrated[canonical]["status"], "leased")
        self.assertEqual(migrated[canonical]["lease_until"], lease_until)

    def test_plain_password_change_does_not_inherit_same_line_legacy_state(self):
        class PoolEntry:
            def __init__(self, **kwargs):
                self.__dict__.update(kwargs)

        class MailboxPoolModule:
            @staticmethod
            def _entry_key(email, identity):
                return hashlib.sha256(
                    f"{email.lower()}\x1f{identity}".encode("utf-8", "ignore")
                ).hexdigest()

        current_row = "same@example.com|casepass"
        previous_row = "SAME@EXAMPLE.COM----CasePass"
        canonical = MailboxPoolModule._entry_key(
            "same@example.com", "outlook::casepass"
        )
        legacy = MailboxPoolModule._entry_key("same@example.com", previous_row)
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            pool_path = root / "pool.txt"
            state_path = root / "state.json"
            pool_path.write_text(current_row + "\n", encoding="utf-8")
            state_path.write_text(
                json.dumps({
                    "items": {
                        legacy: {
                            "email": "same@example.com",
                            "line_no": 1,
                            "status": "consumed",
                            "updated_at": 100,
                        }
                    }
                }),
                encoding="utf-8",
            )
            patches = build_chatgpt_totp_patches(
                runtime_module=SimpleNamespace(
                    PoolEntry=PoolEntry,
                    _mailbox_pool=MailboxPoolModule,
                ),
                codex_oauth_chain=SimpleNamespace(),
                original_entries_unlocked=lambda _pool: ([], ["line 1: bad"]),
                original_outlook_otp_provider=lambda *args, **kwargs: None,
                original_account_label=lambda entry: entry.email,
                original_verify_password=lambda *args: {},
                original_send_mfa_otp=lambda *args: {},
                original_verify_mfa_otp=lambda *args: {},
                parse_oauth_mailbox_row=parse_oauth_mailbox_row,
            )

            entries, errors = patches.entries_unlocked(
                SimpleNamespace(pool_path=pool_path, state_path=state_path)
            )
            preserved = json.loads(state_path.read_text(encoding="utf-8"))["items"]

        self.assertEqual(errors, [])
        self.assertEqual(entries[0].key, canonical)
        self.assertEqual(set(preserved), {legacy})
        self.assertEqual(preserved[legacy]["status"], "consumed")

    def test_url_rows_with_dash_and_pipe_separators_keep_private_source_rows(self):
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
            self.assertEqual(entry.source_row, row)

    def test_totp_mfa_issue_challenge_matches_browser_request(self):
        calls = []

        class FakeTransport:
            def __init__(self):
                self.log_fn = None

            def _post_auth_json(self, path, payload, **kwargs):
                calls.append((path, dict(payload), dict(kwargs)))
                return {"_status": 200}

        chain = SimpleNamespace(
            AUTH="https://auth.openai.com",
            _page_type=lambda response: (response.get("page") or {}).get("type", ""),
            _continue_url=lambda response: response.get("continue_url", ""),
        )
        patches = build_chatgpt_totp_patches(
            runtime_module=SimpleNamespace(),
            codex_oauth_chain=chain,
            original_entries_unlocked=lambda _pool: ([], []),
            original_outlook_otp_provider=lambda *args, **kwargs: None,
            original_account_label=lambda entry: entry.email,
            original_verify_password=lambda *_args: {
                "_status": 200,
                "page": {"payload": {"factor_id": "factor-id"}},
                "continue_url": "https://auth.openai.com/mfa-challenge/factor-id",
            },
            original_send_mfa_otp=lambda *args: {},
            original_verify_mfa_otp=lambda *args: {},
            parse_oauth_mailbox_row=parse_oauth_mailbox_row,
        )
        patches.outlook_otp_provider(
            SimpleNamespace(oauth_client_id="chatgpt_totp", oauth_refresh_token="JBSWY3DPEHPK3PXP"),
            {},
            None,
        )

        transport = FakeTransport()
        patches.verify_password(transport, "password")
        response = patches.send_mfa_otp(
            transport,
            "https://auth.openai.com/mfa-challenge/factor-id",
        )

        self.assertEqual(response["_status"], 200)
        self.assertEqual(calls[0][0], "/api/accounts/mfa/issue_challenge")
        self.assertEqual(
            calls[0][1],
            {"id": "factor-id", "type": "totp", "force_fresh_challenge": False},
        )
        self.assertEqual(calls[0][2]["referer"], "https://auth.openai.com/log-in/password")

    def test_incorrect_totp_keeps_same_challenge_for_the_single_retry(self):
        original_calls = []

        class FakeTransport:
            def __init__(self):
                self.log_fn = None
                self._gptphone_totp_refresh_in_headers = True
                self.responses = [
                    {"_status": 403, "error": {"code": "incorrect_code"}},
                    {"_status": 200, "page": {"type": "consent"}},
                ]
                self.calls = []

            def _post_auth_json(self, path, payload, **kwargs):
                self.calls.append((path, dict(payload), dict(kwargs)))
                return self.responses.pop(0)

        chain = SimpleNamespace(
            AUTH="https://auth.openai.com",
            _page_type=lambda response: (response.get("page") or {}).get("type", ""),
            _continue_url=lambda response: response.get("continue_url", ""),
        )
        patches = build_chatgpt_totp_patches(
            runtime_module=SimpleNamespace(),
            codex_oauth_chain=chain,
            original_entries_unlocked=lambda _pool: ([], []),
            original_outlook_otp_provider=lambda *args, **kwargs: None,
            original_account_label=lambda entry: entry.email,
            original_verify_password=lambda *_args: {
                "_status": 200,
                "page": {"payload": {"factor_id": "factor-id"}},
                "continue_url": "https://auth.openai.com/mfa-challenge/factor-id",
            },
            original_send_mfa_otp=lambda *args: {},
            original_verify_mfa_otp=lambda *args: original_calls.append(args),
            parse_oauth_mailbox_row=parse_oauth_mailbox_row,
        )
        patches.outlook_otp_provider(
            SimpleNamespace(
                oauth_client_id="chatgpt_totp",
                oauth_refresh_token="JBSWY3DPEHPK3PXP",
            ),
            {},
            None,
        )
        transport = FakeTransport()
        patches.verify_password(transport, "password")

        rejected = patches.verify_mfa_otp(transport, "first-code")
        self.assertEqual(rejected["_status"], 403)
        self.assertTrue(transport._gptphone_totp_flow)
        self.assertTrue(transport._gptphone_totp_secret)

        accepted = patches.verify_mfa_otp(transport, "second-code")

        self.assertEqual(accepted["_status"], 200)
        self.assertEqual(len(transport.calls), 2)
        self.assertEqual(original_calls, [])
        self.assertFalse(transport._gptphone_totp_flow)
        self.assertEqual(transport._gptphone_totp_secret, "")

    def test_totp_trace_redacts_unknown_provider_message(self):
        private_message = "provider body private-token-should-not-log"
        logs = []

        class FakeTransport:
            def __init__(self):
                self.log_fn = lambda message, level="info": logs.append((message, level))
                self._gptphone_totp_refresh_in_headers = True

            def _post_auth_json(self, *_args, **_kwargs):
                return {"_status": 403, "error": {"message": private_message}}

        chain = SimpleNamespace(
            AUTH="https://auth.openai.com",
            _page_type=lambda response: (response.get("page") or {}).get("type", ""),
            _continue_url=lambda response: response.get("continue_url", ""),
        )
        patches = build_chatgpt_totp_patches(
            runtime_module=SimpleNamespace(),
            codex_oauth_chain=chain,
            original_entries_unlocked=lambda _pool: ([], []),
            original_outlook_otp_provider=lambda *args, **kwargs: None,
            original_account_label=lambda entry: entry.email,
            original_verify_password=lambda *_args: {
                "_status": 200,
                "page": {"payload": {"factor_id": "factor-id"}},
                "continue_url": "https://auth.openai.com/mfa-challenge/factor-id",
            },
            original_send_mfa_otp=lambda *args: {},
            original_verify_mfa_otp=lambda *args: {},
            parse_oauth_mailbox_row=parse_oauth_mailbox_row,
        )
        patches.outlook_otp_provider(
            SimpleNamespace(oauth_client_id="chatgpt_totp", oauth_refresh_token="JBSWY3DPEHPK3PXP"),
            {},
            None,
        )
        transport = FakeTransport()
        patches.verify_password(transport, "password")
        patches.verify_mfa_otp(transport, "123456")

        self.assertIn("error=provider_error", repr(logs))
        self.assertNotIn(private_message, repr(logs))

    def test_incorrect_totp_waits_for_a_different_time_window(self):
        secret = "JBSWY3DPEHPK3PXP"

        class Clock:
            def __init__(self):
                self.now = 100.0
                self.waits = []

            def time(self):
                return self.now

            def wait(self, seconds):
                self.waits.append(seconds)
                self.now += seconds
                return False

        class StopEvent:
            def __init__(self, clock):
                self.clock = clock

            def is_set(self):
                return False

            def wait(self, seconds):
                return self.clock.wait(seconds)

        class FakeTransport:
            def __init__(self, clock):
                self.clock = clock
                self.log_fn = None
                self._gptphone_totp_refresh_in_headers = True

            def _post_auth_json(self, _path, payload, **_kwargs):
                # Header preparation crossed a TOTP boundary, so this is the
                # code that actually reached the provider and was rejected.
                self.clock.now = 120.0
                payload["code"] = totp_code(secret, now=self.clock.now)
                return {"_status": 403, "error": {"code": "incorrect_code"}}

        clock = Clock()
        stop_event = StopEvent(clock)
        chain = SimpleNamespace(
            AUTH="https://auth.openai.com",
            _page_type=lambda response: (response.get("page") or {}).get("type", ""),
            _continue_url=lambda response: response.get("continue_url", ""),
        )
        with patch("mac_overrides.chatgpt_totp.time.time", side_effect=clock.time):
            patches = build_chatgpt_totp_patches(
                runtime_module=SimpleNamespace(),
                codex_oauth_chain=chain,
                original_entries_unlocked=lambda _pool: ([], []),
                original_outlook_otp_provider=lambda *args, **kwargs: None,
                original_account_label=lambda entry: entry.email,
                original_verify_password=lambda *_args: {
                    "_status": 200,
                    "page": {"payload": {"factor_id": "factor-id"}},
                    "continue_url": "https://auth.openai.com/mfa-challenge/factor-id",
                },
                original_send_mfa_otp=lambda *args: {},
                original_verify_mfa_otp=lambda *args: {},
                parse_oauth_mailbox_row=parse_oauth_mailbox_row,
            )
            provider = patches.outlook_otp_provider(
                SimpleNamespace(
                    source_row=f"totp@example.com|password|{secret}",
                    oauth_client_id="chatgpt_totp",
                    oauth_refresh_token=secret,
                ),
                {},
                None,
                stop_event=stop_event,
            )
            transport = FakeTransport(clock)
            patches.verify_password(transport, "password")

            first_code = provider.wait_code("totp@example.com")
            rejected = patches.verify_mfa_otp(transport, first_code)
            rejected_code = totp_code(secret, now=120.0)
            retry_code = provider.wait_code("totp@example.com")

        self.assertEqual(rejected["_status"], 403)
        self.assertEqual(len(clock.waits), 1)
        self.assertAlmostEqual(clock.waits[0], 30.05, places=2)
        self.assertNotEqual(retry_code, rejected_code)
        self.assertEqual(retry_code, totp_code(secret, now=150.05))

    def test_totp_retry_wait_is_interrupted_by_stop_event(self):
        secret = "JBSWY3DPEHPK3PXP"

        class StopEvent:
            def __init__(self):
                self.stopped = False
                self.waits = []

            def is_set(self):
                return self.stopped

            def wait(self, seconds):
                self.waits.append(seconds)
                self.stopped = True
                return True

        stop_event = StopEvent()
        chain = SimpleNamespace(
            AUTH="https://auth.openai.com",
            _page_type=lambda response: (response.get("page") or {}).get("type", ""),
            _continue_url=lambda response: response.get("continue_url", ""),
        )
        with patch("mac_overrides.chatgpt_totp.time.time", return_value=120.0):
            patches = build_chatgpt_totp_patches(
                runtime_module=SimpleNamespace(),
                codex_oauth_chain=chain,
                original_entries_unlocked=lambda _pool: ([], []),
                original_outlook_otp_provider=lambda *args, **kwargs: None,
                original_account_label=lambda entry: entry.email,
                original_verify_password=lambda *_args: {
                    "_status": 200,
                    "page": {"payload": {"factor_id": "factor-id"}},
                    "continue_url": "https://auth.openai.com/mfa-challenge/factor-id",
                },
                original_send_mfa_otp=lambda *args: {},
                original_verify_mfa_otp=lambda *args: {},
                parse_oauth_mailbox_row=parse_oauth_mailbox_row,
            )
            provider = patches.outlook_otp_provider(
                SimpleNamespace(
                    source_row=f"totp@example.com|password|{secret}",
                    oauth_client_id="chatgpt_totp",
                    oauth_refresh_token=secret,
                ),
                {},
                None,
                stop_event=stop_event,
            )
            transport = SimpleNamespace(
                log_fn=None,
                _gptphone_totp_refresh_in_headers=True,
                _post_auth_json=lambda *_args, **_kwargs: {
                    "_status": 403,
                    "error": {"code": "incorrect_code"},
                },
            )
            patches.verify_password(transport, "password")
            first_code = provider.wait_code("totp@example.com")
            patches.verify_mfa_otp(transport, first_code)

            retry_code = provider.wait_code("totp@example.com")

        self.assertEqual(retry_code, "")
        self.assertEqual(len(stop_event.waits), 1)

    def test_totp_provider_does_not_acquire_shared_mailbox_slot(self):
        class PhaseGate:
            def __init__(self):
                self.calls = 0

            def acquire(self, *_args, **_kwargs):
                self.calls += 1
                raise AssertionError("TOTP must not acquire the mailbox polling slot")

        gate = PhaseGate()
        patches = build_chatgpt_totp_patches(
            runtime_module=SimpleNamespace(),
            codex_oauth_chain=SimpleNamespace(),
            original_entries_unlocked=lambda _pool: ([], []),
            original_outlook_otp_provider=lambda *args, **kwargs: None,
            original_account_label=lambda entry: entry.email,
            original_verify_password=lambda *args: {},
            original_send_mfa_otp=lambda *args: {},
            original_verify_mfa_otp=lambda *args: {},
            parse_oauth_mailbox_row=parse_oauth_mailbox_row,
        )
        provider = patches.outlook_otp_provider(
            SimpleNamespace(
                source_row="totp@example.com|password|JBSWY3DPEHPK3PXP",
                oauth_client_id="chatgpt_totp",
                oauth_refresh_token="JBSWY3DPEHPK3PXP",
            ),
            {},
            None,
            phase_gate=gate,
        )

        self.assertIsNone(provider.acquire_login_slot())
        self.assertEqual(len(provider.wait_code("totp@example.com")), 6)
        self.assertEqual(gate.calls, 0)

    def test_task_reset_prevents_next_account_from_inheriting_totp_flow(self):
        ordinary_provider = object()
        patches = build_chatgpt_totp_patches(
            runtime_module=SimpleNamespace(),
            codex_oauth_chain=SimpleNamespace(),
            original_entries_unlocked=lambda _pool: ([], []),
            original_outlook_otp_provider=lambda *args, **kwargs: ordinary_provider,
            original_account_label=lambda entry: entry.email,
            original_verify_password=lambda *args: {},
            original_send_mfa_otp=lambda *args: {},
            original_verify_mfa_otp=lambda *args: {},
            parse_oauth_mailbox_row=parse_oauth_mailbox_row,
        )
        patches.outlook_otp_provider(
            SimpleNamespace(
                source_row="totp@example.com|password|JBSWY3DPEHPK3PXP",
                oauth_client_id="chatgpt_totp",
                oauth_refresh_token="JBSWY3DPEHPK3PXP",
            ),
            {},
            None,
        )

        patches.reset_task_state()
        self.assertIs(
            patches.outlook_otp_provider(
                SimpleNamespace(
                    source_row="ordinary@example.com|password",
                    oauth_client_id="",
                    oauth_refresh_token="",
                ),
                {},
                None,
            ),
            ordinary_provider,
        )
        transport = SimpleNamespace()
        patches.verify_password(transport, "password")

        self.assertFalse(transport._gptphone_totp_flow)
        self.assertFalse(hasattr(transport, "_gptphone_totp_secret"))

    def test_pending_totp_is_refreshed_after_slow_header_preparation(self):
        payload = {"code": "stale"}
        transport = SimpleNamespace(
            _gptphone_totp_payload=payload,
            _gptphone_totp_secret="JBSWY3DPEHPK3PXP",
        )
        now_values = iter((59.0, 60.05))
        sleeps = []

        refreshed = refresh_transport_totp_payload(
            transport,
            "mfa_otp_verify",
            now_fn=lambda: next(now_values),
            sleep_fn=sleeps.append,
        )

        self.assertTrue(refreshed)
        self.assertAlmostEqual(sleeps[0], 1.05, places=2)
        self.assertEqual(payload["code"], totp_code("JBSWY3DPEHPK3PXP", now=60.05))

    def test_pending_totp_context_restores_transport_state_after_failure(self):
        original_payload = {"code": "original"}
        transport = SimpleNamespace(
            _gptphone_totp_payload=original_payload,
            _gptphone_totp_secret="ORIGINAL",
        )
        payload = {"code": "stale"}

        with self.assertRaisesRegex(RuntimeError, "request failed"):
            with pending_transport_totp_payload(
                transport,
                payload,
                "JBSWY3DPEHPK3PXP",
            ):
                self.assertIs(transport._gptphone_totp_payload, payload)
                self.assertEqual(
                    transport._gptphone_totp_secret,
                    "JBSWY3DPEHPK3PXP",
                )
                raise RuntimeError("request failed")

        self.assertIs(transport._gptphone_totp_payload, original_payload)
        self.assertEqual(transport._gptphone_totp_secret, "ORIGINAL")


if __name__ == "__main__":
    unittest.main()
