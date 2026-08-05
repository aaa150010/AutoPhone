from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from mac_overrides.openai_direct_test_runtime import (
    OPENAI_CODEX_RESPONSES_URL,
    OpenAIDirectTestClient,
    OpenAIDirectTestRuntime,
)


class FakeResponse:
    def __init__(self, status_code=200, *, chunks=()):
        self.status_code = status_code
        self.chunks = list(chunks)
        self.closed = False

    def iter_content(self, chunk_size=1024):
        del chunk_size
        yield from self.chunks

    def close(self):
        self.closed = True


class FakeTransport:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def post(self, url, *, headers, json_body, timeout):
        self.calls.append({"url": url, "headers": dict(headers), "body": dict(json_body), "timeout": timeout})
        return self.responses.pop(0)


def response_events(*events):
    body = "".join(
        f"data: {json.dumps(event, ensure_ascii=False)}\n\n"
        for event in events
    ).encode("utf-8")
    return [body]


def success_document():
    return {
        "status": "success",
        "result": {
            "local_oauth": {
                "tokens": {
                    "access_token": "private-access-token",
                    "chatgpt_account_id": "private-account-id",
                }
            }
        },
    }


class OpenAIDirectTestRuntimeTests(unittest.TestCase):
    def test_success_uses_local_openai_contract_and_not_sub2(self):
        transport = FakeTransport([
            FakeResponse(chunks=response_events({"type": "response.completed"}))
        ])
        client = OpenAIDirectTestClient(transport=transport, sleep_fn=lambda _seconds: None)

        status = client.test_document(success_document())

        self.assertEqual(status.kind, "healthy")
        self.assertEqual(transport.calls[0]["url"], OPENAI_CODEX_RESPONSES_URL)
        self.assertEqual(
            transport.calls[0]["headers"]["authorization"],
            "Bearer private-access-token",
        )
        self.assertEqual(transport.calls[0]["headers"]["chatgpt-account-id"], "private-account-id")
        self.assertEqual(transport.calls[0]["body"]["model"], "gpt-5.4")
        self.assertTrue(transport.calls[0]["body"]["store"] is False)
        self.assertNotIn("private-access-token", str(status))
        self.assertNotIn("private-account-id", str(status))

    def test_incomplete_stream_gets_one_fresh_attempt_before_success(self):
        transport = FakeTransport([
            FakeResponse(chunks=response_events({"type": "response.output_text.delta", "delta": "hi"})),
            FakeResponse(chunks=response_events({"type": "response.completed"})),
        ])
        sleeps = []
        client = OpenAIDirectTestClient(
            transport=transport,
            sleep_fn=sleeps.append,
        )

        status = client.test_document(success_document())

        self.assertEqual(status.kind, "healthy")
        self.assertEqual(len(transport.calls), 2)
        self.assertEqual(len(sleeps), 1)
        self.assertNotEqual(
            transport.calls[0]["headers"]["x-codex-window-id"],
            transport.calls[1]["headers"]["x-codex-window-id"],
        )

    def test_final_incomplete_stream_is_a_remote_disconnect(self):
        transport = FakeTransport([
            FakeResponse(chunks=response_events({"type": "response.output_text.delta", "delta": "hi"})),
            FakeResponse(chunks=response_events({"type": "response.output_text.delta", "delta": "still"})),
        ])
        status = OpenAIDirectTestClient(
            transport=transport,
            sleep_fn=lambda _seconds: None,
        ).test_document(success_document())

        self.assertEqual(status.kind, "remote_disconnected")
        self.assertIn("完成前断开", status.summary)

    def test_http_statuses_are_not_misreported_as_sub2_account_states(self):
        cases = ((401, "unauthorized"), (404, "http_error"), (429, "rate_limited"))
        for code, expected_kind in cases:
            with self.subTest(code=code):
                transport = FakeTransport([FakeResponse(code)])
                status = OpenAIDirectTestClient(transport=transport).test_document(success_document())
                self.assertEqual(status.kind, expected_kind)

    def test_runtime_marks_unuploaded_rows_without_sending_a_request(self):
        with tempfile.TemporaryDirectory() as temp:
            factory_calls = []

            def factory(**kwargs):
                factory_calls.append(kwargs)
                return OpenAIDirectTestClient(transport=FakeTransport([]), **kwargs)

            runtime = OpenAIDirectTestRuntime(
                lambda: {"proxy": "http://proxy.example.test:8080"},
                Path(temp) / "snapshots.json",
                client_factory=factory,
            )
            result = runtime.test_rows(
                [
                    {
                        "row_id": "row-unuploaded",
                        "line_no": 1,
                        "sub2api_account_id": "",
                        "document": {},
                    }
                ]
            )

        self.assertEqual(result["not_ready"], 1)
        self.assertEqual(result["unlinked"], 1)
        self.assertEqual(result["results"][0]["sub2_status"]["label"], "未上传，无法直连 OpenAI")
        self.assertEqual(len(factory_calls), 0)

    def test_runtime_status_for_returns_persisted_public_status(self):
        with tempfile.TemporaryDirectory() as temp:
            snapshot_path = Path(temp) / "snapshots.json"
            transport = FakeTransport([
                FakeResponse(chunks=response_events({"type": "response.completed"}))
            ])

            def factory(**kwargs):
                return OpenAIDirectTestClient(transport=transport, **kwargs)

            runtime = OpenAIDirectTestRuntime(
                lambda: {},
                snapshot_path,
                client_factory=factory,
            )
            runtime.test_rows(
                [
                    {
                        "row_id": "row-linked",
                        "line_no": 1,
                        "sub2api_account_id": "",
                        "openai_status_id": "openai-account-1",
                        "document": success_document(),
                    }
                ]
            )

            reloaded = OpenAIDirectTestRuntime(lambda: {}, snapshot_path)
            status = reloaded.status_for("openai-account-1")
            serialized = snapshot_path.read_text(encoding="utf-8")

        self.assertIsInstance(status, dict)
        self.assertEqual(status["kind"], "healthy")
        self.assertEqual(status["status_code"], 200)
        self.assertNotIn("openai-account-1", serialized)
        self.assertNotIn("private-access-token", json.dumps(status))
        self.assertNotIn("private-account-id", json.dumps(status))


if __name__ == "__main__":
    unittest.main()
