from __future__ import annotations

import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

from mac_overrides.openai_quota_runtime import (
    OPENAI_CODEX_RESPONSES_URL,
    OPENAI_USAGE_URL,
    OpenAIQuotaClient,
    OpenAIQuotaError,
    OpenAIQuotaSnapshotStore,
    credentials_from_result,
    normalize_quota_headers,
    normalize_quota_payload,
)


class FakeTransport:
    def __init__(self, payload=None, status=200, error=None, probe_headers=None, probe_error=None):
        self.payload = payload
        self.status = status
        self.error = error
        self.probe_headers = probe_headers
        self.probe_error = probe_error
        self.calls = []
        self.probe_calls = []

    def get(self, url, *, headers, timeout):
        self.calls.append((url, dict(headers), timeout))
        if self.error:
            raise self.error
        return SimpleNamespace(status_code=self.status, json=lambda: self.payload)

    def post(self, url, *, headers, json_body, timeout):
        self.probe_calls.append((url, dict(headers), dict(json_body), timeout))
        if self.probe_error:
            raise self.probe_error
        return SimpleNamespace(status_code=429, headers=self.probe_headers or {})


def success_document():
    return {
        "status": "success",
        "result": {
            "local_oauth": {
                "tokens": {
                    "access_token": "access-secret",
                    "chatgpt_account_id": "account-secret",
                }
            }
        },
    }


class OpenAIQuotaRuntimeTests(unittest.TestCase):
    def test_snapshot_preserves_last_percentages_after_failure_without_account_secrets(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "quota-snapshots.json"
            clock = [100]
            store = OpenAIQuotaSnapshotStore(path, now_fn=lambda: clock[0])
            store.put(
                "private-account-id",
                {
                    "status": "ok",
                    "quota_5h": {"remaining_percent": 80, "queried_at": 100},
                    "quota_7d": {"remaining_percent": 40, "queried_at": 100},
                    "queried_at": 100,
                    "access_token": "private-access-token",
                },
            )
            clock[0] = 200
            failed = store.put(
                "private-account-id",
                {
                    "status": "error",
                    "code": "openai_quota_network_error",
                    "error": "查询 OpenAI 额度失败：网络不可用",
                    "queried_at": 200,
                },
            )

            reloaded = OpenAIQuotaSnapshotStore(path).status_for("private-account-id")
            serialized = path.read_text(encoding="utf-8")

        self.assertEqual(failed["status"], "error")
        self.assertEqual(failed["quota_5h"]["remaining_percent"], 80)
        self.assertEqual(failed["quota_7d"]["remaining_percent"], 40)
        self.assertEqual(reloaded, failed)
        self.assertNotIn("private-account-id", serialized)
        self.assertNotIn("private-access-token", serialized)
        self.assertEqual(len(json.loads(serialized)["items"]), 1)

    def test_query_matches_codex_headers_and_returns_remaining_percent(self):
        transport = FakeTransport({
            "rate_limit": {
                "primary_window": {
                    "used_percent": 25,
                    "limit_window_seconds": 604800,
                    "reset_after_seconds": 400,
                    "reset_at": 2000,
                },
                "secondary_window": {
                    "used_percent": 80.5,
                    "limit_window_seconds": 18000,
                    "reset_after_seconds": 100,
                    "reset_at": 1500,
                },
            }
        })
        client = OpenAIQuotaClient(transport=transport, now_fn=lambda: 1234)

        result = client.query(success_document())

        self.assertEqual(result["quota_5h"]["remaining_percent"], 19.5)
        self.assertEqual(result["quota_7d"]["remaining_percent"], 75.0)
        self.assertEqual(result["queried_at"], 1234)
        url, headers, timeout = transport.calls[0]
        self.assertEqual(url, OPENAI_USAGE_URL)
        self.assertEqual(headers["authorization"], "Bearer access-secret")
        self.assertEqual(headers["chatgpt-account-id"], "account-secret")
        self.assertEqual(headers["openai-beta"], "codex-1")
        self.assertEqual(headers["originator"], "Codex Desktop")
        self.assertEqual(timeout, 20)
        self.assertNotIn("access-secret", str(result))
        self.assertNotIn("account-secret", str(result))

    def test_window_order_is_determined_by_duration(self):
        normalized = normalize_quota_payload({
            "rate_limit": {
                "primary_window": {"used_percent": 5, "limit_window_seconds": 18000},
                "secondary_window": {"used_percent": 10, "limit_window_seconds": 604800},
            }
        }, queried_at=50)

        self.assertEqual(normalized["quota_5h"]["remaining_percent"], 95)
        self.assertEqual(normalized["quota_7d"]["remaining_percent"], 90)

    def test_single_window_and_percent_clamping(self):
        normalized = normalize_quota_payload({
            "rate_limit": {
                "primary_window": {"used_percent": 120, "limit_window_seconds": 18000},
            }
        }, queried_at=50)

        self.assertEqual(normalized["quota_5h"]["remaining_percent"], 0)
        self.assertIsNone(normalized["quota_7d"])

    def test_missing_five_hour_window_is_filled_from_codex_probe_headers(self):
        transport = FakeTransport(
            {
                "rate_limit": {
                    "primary_window": {
                        "used_percent": 25,
                        "limit_window_seconds": 604800,
                        "reset_after_seconds": 400,
                    },
                    "secondary_window": None,
                }
            },
            probe_headers={
                "X-Codex-Primary-Used-Percent": "25",
                "X-Codex-Primary-Window-Minutes": "10080",
                "X-Codex-Primary-Reset-After-Seconds": "400",
                "X-Codex-Secondary-Used-Percent": "0",
                "X-Codex-Secondary-Window-Minutes": "0",
                "X-Codex-Secondary-Reset-After-Seconds": "0",
            },
        )
        client = OpenAIQuotaClient(transport=transport, now_fn=lambda: 1234)

        result = client.query(success_document())

        self.assertEqual(result["quota_5h"]["remaining_percent"], 100)
        self.assertEqual(result["quota_5h"]["limit_window_seconds"], 0)
        self.assertEqual(result["quota_7d"]["remaining_percent"], 75)
        self.assertEqual(len(transport.probe_calls), 1)
        url, headers, body, timeout = transport.probe_calls[0]
        self.assertEqual(url, OPENAI_CODEX_RESPONSES_URL)
        self.assertEqual(headers["authorization"], "Bearer access-secret")
        self.assertEqual(headers["chatgpt-account-id"], "account-secret")
        self.assertEqual(body["model"], "gpt-5.4")
        self.assertTrue(body["stream"])
        self.assertEqual(timeout, 20)
        self.assertNotIn("access-secret", str(result))

    def test_probe_failure_preserves_wham_window(self):
        transport = FakeTransport(
            {
                "rate_limit": {
                    "primary_window": {
                        "used_percent": 40,
                        "limit_window_seconds": 604800,
                    }
                }
            },
            probe_error=RuntimeError("probe failed with access-secret"),
        )
        result = OpenAIQuotaClient(transport=transport, now_fn=lambda: 50).query(success_document())

        self.assertIsNone(result["quota_5h"])
        self.assertEqual(result["quota_7d"]["remaining_percent"], 60)
        self.assertNotIn("access-secret", str(result))

    def test_header_normalization_orders_windows_by_duration(self):
        result = normalize_quota_headers({
            "x-codex-primary-used-percent": "20",
            "x-codex-primary-window-minutes": "10080",
            "x-codex-secondary-used-percent": "3",
            "x-codex-secondary-window-minutes": "300",
        }, queried_at=50)

        self.assertEqual(result["quota_5h"]["remaining_percent"], 97)
        self.assertEqual(result["quota_7d"]["remaining_percent"], 80)

    def test_missing_credentials_returns_stable_redacted_error(self):
        with self.assertRaises(OpenAIQuotaError) as raised:
            credentials_from_result({"result": {"access_token": ""}})

        public = raised.exception.public()
        self.assertEqual(public["node_code"], "openai_quota")
        self.assertEqual(public["code"], "openai_quota_token_missing")

    def test_upstream_status_does_not_publish_credentials_or_body(self):
        transport = FakeTransport({"secret": "upstream-body"}, status=401)
        client = OpenAIQuotaClient(transport=transport)

        with self.assertRaises(OpenAIQuotaError) as raised:
            client.query(success_document())

        public = raised.exception.public()
        serialized = str(public)
        self.assertEqual(public["code"], "openai_quota_unauthorized")
        self.assertNotIn("access-secret", serialized)
        self.assertNotIn("account-secret", serialized)
        self.assertNotIn("upstream-body", serialized)


if __name__ == "__main__":
    unittest.main()
