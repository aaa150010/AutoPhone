from __future__ import annotations

import json
from pathlib import Path
import stat
import tempfile
import unittest

from flask import Flask, jsonify, request

from mac_overrides.mailbox_parser_sample_routes import MailboxParserSampleRouteController
from mac_overrides.mailbox_parser_sample_store import (
    MAX_ARTIFACT_BYTES,
    MAX_SAMPLE_BYTES,
    MailboxParserSampleStore,
    configure_sample_stores,
)
from mac_overrides.mailbox_otp_service import MailboxOtpError, MailboxOtpService
from mac_overrides.mailbox_url_runtime import MailboxResponse
import mac_overrides.mailbox_parser_sample_store as sample_store_module


def _sample(url: str = "https://mail.example.test/pickup?key=private") -> dict:
    return {
        "scope": "ordinary",
        "chain": "ordinary",
        "workflow": "login",
        "driver": "sms_oauth",
        "task_id": "task-1",
        "batch_id": "batch-1",
        "stage": "email_code_waiting",
        "mailbox_url": url,
        "reason": "mailbox_openai_message_without_otp",
        "diagnostics": {"listing_messages": 1, "openai_messages": 1},
        "parser_version": "pickup-dynamic-v7-samples",
    }


def _response(body: bytes, *, role: str = "entry", url: str = "https://mail.example.test/inbox") -> dict:
    return {
        "request_role": role,
        "request_url": url,
        "response_url": url,
        "status": 200,
        "content_type": "application/json; charset=utf-8",
        "body": body,
    }


class MailboxParserSampleStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.store = MailboxParserSampleStore(Path(self.tempdir.name) / "samples")

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def test_permissions_and_raw_artifacts_are_separate_from_list_shape(self) -> None:
        sample_id = self.store.record_failure(_sample(), [_response(b'{"messages":[]}')])
        self.assertTrue(sample_id.startswith("MPS-"))
        self.assertEqual(stat.S_IMODE((Path(self.tempdir.name) / "samples").stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(self.store.path.stat().st_mode), 0o600)
        listed = self.store.list()[0]
        self.assertNotIn("responses", listed)
        detail = self.store.get(sample_id, include_responses=True, include_body=True)
        self.assertEqual(detail["mailbox_url"], _sample()["mailbox_url"])
        self.assertEqual(detail["responses"][0]["body_text"], '{"messages":[]}')

    def test_deduplicates_sample_but_keeps_distinct_response_roles(self) -> None:
        body = b'{"messages":[]}'
        first = self.store.record_failure(_sample(), [_response(body, role="entry")])
        second = self.store.record_failure(_sample(), [_response(body, role="detail", url="https://mail.example.test/detail")])
        self.assertEqual(first, second)
        detail = self.store.get(first, include_responses=True)
        self.assertEqual(detail["occurrence_count"], 2)
        self.assertEqual(detail["response_count"], 2)
        self.assertEqual({row["request_role"] for row in detail["responses"]}, {"entry", "detail"})

    def test_sample_and_response_limits_mark_truncation(self) -> None:
        body = b"x" * (MAX_SAMPLE_BYTES + 1)
        sample_id = self.store.record_failure(_sample(), [_response(body)])
        detail = self.store.get(sample_id, include_responses=True)
        self.assertTrue(detail["truncated"])
        self.assertLessEqual(detail["responses"][0]["body_bytes"], MAX_ARTIFACT_BYTES)
        self.assertLessEqual(detail["total_bytes"], MAX_SAMPLE_BYTES)

    def test_cleanup_deletes_cascade_rows_and_respects_byte_limit(self) -> None:
        store = MailboxParserSampleStore(Path(self.tempdir.name) / "bounded")
        first = store.record_failure(_sample("https://mail.example.test/one"), [_response(b"a" * 80)])
        second = store.record_failure(_sample("https://mail.example.test/two"), [_response(b"b" * 80)])
        store.max_bytes = 100
        store.update_status([first], "resolved")
        store.cleanup()
        self.assertIsNone(store.get(first))
        self.assertIsNotNone(store.get(second))
        with store._connection() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM mailbox_parser_sample_responses").fetchone()[0], 1)
        store.delete([second])
        with store._connection() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM mailbox_parser_sample_responses").fetchone()[0], 0)


class MailboxParserSampleRouteTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.store = MailboxParserSampleStore(Path(self.tempdir.name) / "samples")
        self.sample_id = self.store.record_failure(
            _sample(),
            [_response(b'{"messages":[{"fromAddress":"noreply@openai.test","subject":"ChatGPT login code","body":"code unavailable"}]}')],
        )
        self.app = Flask(__name__)
        module = type("Module", (), {"request": request, "jsonify": staticmethod(jsonify)})
        controller = MailboxParserSampleRouteController(module=module, ordinary_store=self.store, free_store=None)
        self.app.add_url_rule("/samples", view_func=controller.list, methods=["GET"])
        self.app.add_url_rule("/samples/<sample_id>", view_func=controller.detail, methods=["GET"])
        self.app.add_url_rule("/samples/<sample_id>/reveal", view_func=controller.reveal, methods=["POST"])
        self.app.add_url_rule("/samples/<sample_id>/reparse", view_func=controller.reparse, methods=["POST"])
        self.app.add_url_rule("/samples/export", view_func=controller.export, methods=["POST"])

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def test_list_and_detail_never_expose_raw_urls_or_bodies(self) -> None:
        client = self.app.test_client()
        listed = client.get("/samples").get_json()
        self.assertNotIn("mailbox_url", listed["samples"][0])
        detail = client.get(f"/samples/{self.sample_id}").get_json()["sample"]
        self.assertNotIn("mailbox_url", detail)
        self.assertNotIn("request_url", detail["responses"][0])
        self.assertNotIn("body_text", detail["responses"][0])

    def test_raw_access_requires_loopback_and_explicit_confirmation(self) -> None:
        client = self.app.test_client()
        self.assertEqual(client.post(f"/samples/{self.sample_id}/reveal", json={}).status_code, 400)
        self.assertEqual(client.post(f"/samples/{self.sample_id}/reveal", json={"confirm_raw": True}, environ_base={"REMOTE_ADDR": "10.0.0.2"}).status_code, 403)
        raw = client.post(f"/samples/{self.sample_id}/reveal", json={"confirm_raw": True}).get_json()["sample"]
        self.assertEqual(raw["mailbox_url"], _sample()["mailbox_url"])
        self.assertIn("body_text", raw["responses"][0])
        self.assertEqual(client.post("/samples/export", json={"sample_id": self.sample_id, "format": "fixture"}).status_code, 400)
        fixture = client.post("/samples/export", json={"sample_id": self.sample_id, "format": "fixture", "confirm_raw": True}).get_json()
        self.assertIn("mailbox_url", fixture["content"])

    def test_sanitized_export_and_offline_reparse_do_not_return_raw_values(self) -> None:
        client = self.app.test_client()
        exported = client.post("/samples/export", json={"sample_id": self.sample_id}).get_json()
        self.assertNotIn("mail.example.test", exported["content"])
        reparsed = client.post(f"/samples/{self.sample_id}/reparse").get_json()["reparse"]
        self.assertIn("detail_url_fingerprints", reparsed)
        self.assertNotIn("mail.example.test", json.dumps(reparsed))

    def test_offline_reparse_recognizes_api798_nested_data_code(self) -> None:
        source_url = (
            "https://api798.com/get_code?"
            "email=user%40example.test&auth_code=private-access"
        )
        payload = json.dumps({
            "success": True,
            "data": {
                "body": "Your ChatGPT verification code is 071618.",
                "code": "071618",
                "subject": "ChatGPT temporary verification code",
                "from": "noreply@openai.com",
            },
        }).encode("utf-8")
        sample_id = self.store.record_failure(
            _sample(source_url),
            [_response(payload, url=source_url)],
        )

        reparsed = self.app.test_client().post(
            f"/samples/{sample_id}/reparse"
        ).get_json()["reparse"]

        self.assertEqual(reparsed["code_message_count"], 1)
        self.assertTrue(reparsed["messages"][0]["code_present"])
        self.assertEqual(reparsed["messages"][0]["code_source"], "explicit_code")
        self.assertNotIn("071618", json.dumps(reparsed))


class MailboxParserSampleCaptureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.store = MailboxParserSampleStore(Path(self.tempdir.name) / "samples")
        configure_sample_stores(ordinary=self.store)

    def tearDown(self) -> None:
        sample_store_module._STORES.pop("ordinary", None)
        self.tempdir.cleanup()

    def test_final_no_code_captures_post_baseline_response(self) -> None:
        clock = [0.0]
        responses = iter([
            MailboxResponse("https://mail.example.test/inbox", b"[]", "application/json", 200),
            MailboxResponse("https://mail.example.test/inbox", b'{"messages":[{"fromAddress":"noreply@openai.test","subject":"ChatGPT login code","body":"no code"}]}', "application/json", 200),
        ])

        def fetch(_url: str) -> MailboxResponse:
            try:
                return next(responses)
            except StopIteration:
                return MailboxResponse("https://mail.example.test/inbox", b'{"messages":[{"fromAddress":"noreply@openai.test","subject":"ChatGPT login code","body":"no code"}]}', "application/json", 200)

        service = MailboxOtpService(
            "https://mail.example.test/inbox",
            timeout_seconds=5,
            poll_interval_seconds=5,
            fetcher=fetch,
            now_fn=lambda: clock[0],
            monotonic_fn=lambda: clock[0],
            sleep_fn=lambda seconds: clock.__setitem__(0, clock[0] + seconds),
        )
        service.prepare()
        with self.assertRaises(MailboxOtpError):
            service.wait_code()
        rows = self.store.list()
        self.assertEqual(len(rows), 1)
        detail = self.store.get(rows[0]["sample_id"], include_responses=True, include_body=True)
        self.assertNotEqual(detail["responses"][0]["body_text"], "[]")
        service.close()

    def test_successful_code_and_transport_only_failure_do_not_capture(self) -> None:
        code_body = b'{"messages":[{"fromAddress":"noreply@openai.test","subject":"ChatGPT login code","body":"code 314159"}]}'
        sequence = iter([
            MailboxResponse("https://mail.example.test/inbox", b"[]", "application/json", 200),
            MailboxResponse("https://mail.example.test/inbox", code_body, "application/json", 200),
        ])
        service = MailboxOtpService("https://mail.example.test/inbox", timeout_seconds=5, poll_interval_seconds=5, fetcher=lambda _url: next(sequence))
        service.prepare()
        self.assertEqual(service.wait_code(), "314159")
        service.close()
        self.assertEqual(self.store.count(), 0)

        failing = MailboxOtpService(
            "https://mail.example.test/inbox",
            timeout_seconds=5,
            fetcher=lambda url: MailboxResponse(url, b"", "application/json", 403),
        )
        with self.assertRaises(MailboxOtpError):
            failing.prepare()
        failing.close()
        self.assertEqual(self.store.count(), 0)


if __name__ == "__main__":
    unittest.main()
