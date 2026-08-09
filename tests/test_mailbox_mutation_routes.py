from __future__ import annotations

import unittest

from flask import Flask, jsonify, request

from mac_overrides.mailbox_mutation_routes import MailboxMutationRouteController
from mac_overrides.mailbox_source_lock import MailboxSourceLockTimeout


class FakeLogs:
    def __init__(self) -> None:
        self.rows: list[tuple[str, str]] = []

    def add(self, message: str, level: str = "info") -> None:
        self.rows.append((message, level))


class FakeMailboxAdmin:
    def __init__(self) -> None:
        self.list_calls = 0
        self.import_error: Exception | None = None

    def import_mailboxes(self, content: str):
        if self.import_error is not None:
            raise self.import_error
        return {"ok": True, "imported": int(bool(content)), "skipped": 0}

    def list_mailboxes(self):
        self.list_calls += 1
        return {"ok": True, "counts": {"total": 1}, "rows": []}

    def delete_mailboxes(self, _payload):
        return {"ok": True, "deleted": 1}

    def restore_mailboxes(self, _payload):
        return {"ok": True, "restored": 1}


class MailboxMutationRouteTests(unittest.TestCase):
    def setUp(self) -> None:
        self.app = Flask(__name__)
        self.module = type(
            "FlaskModule",
            (),
            {"request": request, "jsonify": staticmethod(jsonify)},
        )
        self.admin = FakeMailboxAdmin()
        self.logs = FakeLogs()
        self.controller = MailboxMutationRouteController(
            module=self.module,
            mailbox_admin=self.admin,
            public_state=lambda: {"runtime": {"running": False}},
            logs=self.logs,
            safe_error=lambda exc: str(exc),
        )
        self.app.add_url_rule(
            "/import",
            "import_mailboxes",
            self.controller.import_mailboxes,
            methods=["POST"],
        )
        self.app.add_url_rule(
            "/delete",
            "delete_mailboxes",
            self.controller.delete_mailboxes,
            methods=["POST"],
        )

    def test_import_acknowledges_write_without_synchronous_list_scan(self):
        response = self.app.test_client().post(
            "/import",
            json={"pool_content": "user@example.test---https://mail.example.test/token"},
        )

        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["imported"], 1)
        self.assertTrue(payload["mailboxes_refresh_required"])
        self.assertNotIn("mailboxes", payload)
        self.assertNotIn("state", payload)
        self.assertEqual(self.admin.list_calls, 0)

    def test_import_source_lock_timeout_is_a_diagnostic_409(self):
        self.admin.import_error = MailboxSourceLockTimeout("source", 0.1)

        response = self.app.test_client().post(
            "/import",
            json={"pool_content": "user@example.test----password"},
        )

        self.assertEqual(response.status_code, 409)
        payload = response.get_json()
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["code"], "mailbox_source_lock_timeout")
        self.assertEqual(payload["node_code"], "mailbox_source_lock")
        self.assertEqual(payload["node_label"], "邮箱池源文件锁")
        self.assertNotIn("user@example.test", payload["error"])

    def test_other_mutations_keep_enriched_mailbox_and_state_response(self):
        response = self.app.test_client().post("/delete", json={"line_nos": [1]})

        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["deleted"], 1)
        self.assertEqual(payload["mailboxes"]["counts"]["total"], 1)
        self.assertFalse(payload["state"]["runtime"]["running"])
        self.assertEqual(self.admin.list_calls, 1)

    def test_rejects_non_object_json(self):
        response = self.app.test_client().post("/import", json=["invalid"])

        self.assertEqual(response.status_code, 400)
        self.assertFalse(response.get_json()["ok"])


if __name__ == "__main__":
    unittest.main()
