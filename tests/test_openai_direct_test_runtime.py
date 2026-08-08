from __future__ import annotations

import json
from pathlib import Path
import tempfile
import threading
import unittest

from mac_overrides.openai_direct_test_runtime import (
    DIRECT_TEST_FINGERPRINT,
    OPENAI_CODEX_RESPONSES_URL,
    OpenAIDirectTestClient,
    OpenAIDirectTestRuntime,
    _status_from_direct_code,
)
from mac_overrides.openai_row_status import row_status_key


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


def success_document(
    account_id="private-account-id",
    access_token="private-access-token",
):
    return {
        "status": "success",
        "result": {
            "local_oauth": {
                "tokens": {
                    "access_token": access_token,
                    "chatgpt_account_id": account_id,
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
            completed = []
            snapshot_path = Path(temp) / "snapshots.json"

            def factory(**kwargs):
                factory_calls.append(kwargs)
                return OpenAIDirectTestClient(transport=FakeTransport([]), **kwargs)

            runtime = OpenAIDirectTestRuntime(
                lambda: {"proxy": "http://proxy.example.test:8080"},
                snapshot_path,
                client_factory=factory,
            )
            result = runtime.test_rows(
                [
                    {
                        "row_id": "row-unuploaded",
                        "line_no": 1,
                        "sub2api_account_id": "",
                        "document": {},
                        "_on_row_completed": completed.append,
                    }
                ]
            )

            reloaded = OpenAIDirectTestRuntime(lambda: {}, snapshot_path)
            persisted = reloaded.status_for(row_status_key("row-unuploaded"))

        self.assertEqual(result["not_ready"], 1)
        self.assertEqual(result["unlinked"], 1)
        self.assertEqual(result["results"][0]["sub2_status"]["label"], "未上传，无法直连 OpenAI")
        self.assertEqual(persisted["kind"], "not_ready")
        self.assertEqual(completed, result["results"])
        self.assertEqual(len(factory_calls), 0)

    def test_not_ready_row_is_persisted_while_ready_peer_is_blocked(self):
        with tempfile.TemporaryDirectory() as temp:
            ready_started = threading.Event()
            release_ready = threading.Event()
            not_ready_completed = threading.Event()
            snapshot_path = Path(temp) / "snapshots.json"

            class BlockingTransport:
                def post(_self, _url, *, headers, json_body, timeout):
                    del headers, json_body, timeout
                    ready_started.set()
                    release_ready.wait(2)
                    return FakeResponse(chunks=response_events({"type": "response.completed"}))

            runtime = OpenAIDirectTestRuntime(
                lambda: {},
                snapshot_path,
                client_factory=lambda **kwargs: OpenAIDirectTestClient(
                    transport=BlockingTransport(),
                    **kwargs,
                ),
            )

            def completed(item):
                if item["row_id"] == "row-not-ready":
                    not_ready_completed.set()

            worker = threading.Thread(target=lambda: runtime.test_rows([
                {
                    "row_id": "row-ready",
                    "line_no": 1,
                    "openai_status_id": "openai-account-ready",
                    "document": success_document("openai-account-ready"),
                    "_on_row_completed": completed,
                },
                {
                    "row_id": "row-not-ready",
                    "line_no": 2,
                    "document": {},
                    "_on_row_completed": completed,
                },
            ]))
            worker.start()
            try:
                self.assertTrue(not_ready_completed.wait(1))
                self.assertTrue(ready_started.wait(1))
                self.assertTrue(worker.is_alive())
                reloaded = OpenAIDirectTestRuntime(lambda: {}, snapshot_path)
                self.assertEqual(
                    reloaded.status_for(row_status_key("row-not-ready"))["kind"],
                    "not_ready",
                )
            finally:
                release_ready.set()
                worker.join(2)

            self.assertFalse(worker.is_alive())

    def test_not_ready_replaces_old_account_snapshot_immediately(self):
        with tempfile.TemporaryDirectory() as temp:
            snapshot_path = Path(temp) / "snapshots.json"
            runtime = OpenAIDirectTestRuntime(lambda: {}, snapshot_path)
            runtime.snapshot_store.put_many(
                DIRECT_TEST_FINGERPRINT,
                {
                    runtime._snapshot_key("legacy-account"): _status_from_direct_code(401, 100),
                },
            )

            runtime.test_rows([
                {
                    "row_id": "row-not-ready",
                    "line_no": 1,
                    "sub2api_account_id": "legacy-account",
                    "document": {},
                }
            ])

            reloaded = OpenAIDirectTestRuntime(lambda: {}, snapshot_path)
            self.assertEqual(reloaded.status_for("legacy-account")["kind"], "not_ready")

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

    def test_runtime_persists_each_completed_row_before_batch_finishes(self):
        with tempfile.TemporaryDirectory() as temp:
            second_started = threading.Event()
            release_second = threading.Event()
            first_persisted = threading.Event()
            snapshot_path = Path(temp) / "snapshots.json"

            class BlockingTransport:
                def post(_self, _url, *, headers, json_body, timeout):
                    del json_body, timeout
                    if headers["chatgpt-account-id"] == "openai-account-2":
                        second_started.set()
                        release_second.wait(2)
                    return FakeResponse(chunks=response_events({"type": "response.completed"}))

            runtime = OpenAIDirectTestRuntime(
                lambda: {},
                snapshot_path,
                client_factory=lambda **kwargs: OpenAIDirectTestClient(
                    transport=BlockingTransport(),
                    **kwargs,
                ),
            )
            original_put_many = runtime.snapshot_store.put_many

            def put_many(fingerprint, values):
                original_put_many(fingerprint, values)
                if runtime._snapshot_key("openai-account-1") in values:
                    first_persisted.set()

            runtime.snapshot_store.put_many = put_many
            rows = [
                {
                    "row_id": f"row-{index}",
                    "line_no": index,
                    "openai_status_id": f"openai-account-{index}",
                    "document": success_document(
                        f"openai-account-{index}",
                        f"private-access-{index}",
                    ),
                }
                for index in (1, 2)
            ]
            completed = []
            worker = threading.Thread(target=lambda: completed.append(runtime.test_rows(rows)))
            worker.start()
            try:
                self.assertTrue(second_started.wait(1))
                self.assertTrue(first_persisted.wait(1))
                self.assertTrue(worker.is_alive())
                self.assertEqual(runtime.status_for("openai-account-1")["kind"], "healthy")
                reloaded = OpenAIDirectTestRuntime(lambda: {}, snapshot_path)
                self.assertEqual(reloaded.status_for("openai-account-1")["kind"], "healthy")
                self.assertEqual(runtime.status_for("openai-account-2")["kind"], "untested")
            finally:
                release_second.set()
                worker.join(2)

            self.assertFalse(worker.is_alive())
            self.assertEqual(completed[0]["tested"], 2)
            self.assertEqual(runtime.status_for("openai-account-2")["kind"], "healthy")

    def test_mark_credentials_refreshed_replaces_stale_401_without_claiming_healthy(self):
        with tempfile.TemporaryDirectory() as temp:
            snapshot_path = Path(temp) / "snapshots.json"
            runtime = OpenAIDirectTestRuntime(lambda: {}, snapshot_path, now_fn=lambda: 1234)
            runtime.snapshot_store.put_many(
                DIRECT_TEST_FINGERPRINT,
                {
                    runtime._snapshot_key("openai-account-1"): _status_from_direct_code(
                        401,
                        1000,
                    )
                },
            )

            runtime.mark_credentials_refreshed("openai-account-1")
            status = runtime.status_for("openai-account-1")
            serialized = snapshot_path.read_text(encoding="utf-8")

        self.assertEqual(status["kind"], "untested")
        self.assertIsNone(status["status_code"])
        self.assertEqual(status["label"], "凭据已更新，待复测")
        self.assertFalse(status["needs_rerun"])
        self.assertFalse(status["is_error"])
        self.assertNotIn("openai-account-1", serialized)


if __name__ == "__main__":
    unittest.main()
