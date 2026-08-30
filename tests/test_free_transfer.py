from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
import tempfile
import threading
import unittest

import flask
from flask import Flask, jsonify

from mac_overrides.free_pool_routes import FreePoolRouteController
from mac_overrides.free_register_runtime import FreeRegisterManager
from mac_overrides.free_register_store import FreeMailboxPool


class FreeTransferTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="gptphone-free-transfer-")
        self.data_dir = Path(self.temp.name)
        self.pool = FreeMailboxPool(self.data_dir)
        self.pool.import_text(
            "\n".join(
                (
                    "with-password@example.test----https://mail.example.test/password",
                    "with-totp@example.test----https://mail.example.test/totp",
                    "passwordless@example.test----https://mail.example.test/passwordless",
                    "passwordless-totp@example.test----https://mail.example.test/passwordless-totp",
                    "running@example.test----https://mail.example.test/running",
                    "missing@example.test----https://mail.example.test/missing",
                )
            )
        )
        results = {
            "with-password@example.test": {"status": "success", "password": "real-openai-password"},
            "with-totp@example.test": {"status": "success", "password": "real-openai-password", "totp_secret": "JBSWY3DPEHPK3PXP"},
            "passwordless@example.test": {"status": "success"},
            "passwordless-totp@example.test": {"status": "success", "totp_secret": "JBSWY3DPEHPK3PXP"},
            "running@example.test": {"status": "success"},
        }
        for entry in self.pool.entries():
            result = results.get(entry.email)
            if result is not None:
                self.pool.save_result(entry.row_id, result)
                self.pool.update(entry.row_id, status="running" if entry.email == "running@example.test" else "success")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _row(self, email: str):
        return next(row for row in self.pool.entries() if row.email == email)

    def test_build_transfer_content_emits_real_password_and_passwordless_shapes(self) -> None:
        row_ids = [row.row_id for row in self.pool.entries()[:4]]
        full = self.pool.build_transfer_content(row_ids)
        self.assertEqual(
            full["content"].splitlines(),
            [
                "with-password@example.test----real-openai-password",
                "with-totp@example.test----real-openai-password----JBSWY3DPEHPK3PXP",
                "passwordless@example.test----https://mail.example.test/passwordless",
                "passwordless-totp@example.test----https://mail.example.test/passwordless-totp----JBSWY3DPEHPK3PXP",
            ],
        )
        mailbox_only = self.pool.build_transfer_content(row_ids, include_password=False)
        self.assertEqual(
            mailbox_only["content"].splitlines(),
            [
                "with-password@example.test----https://mail.example.test/password",
                "with-totp@example.test----https://mail.example.test/totp----JBSWY3DPEHPK3PXP",
                "passwordless@example.test----https://mail.example.test/passwordless",
                "passwordless-totp@example.test----https://mail.example.test/passwordless-totp----JBSWY3DPEHPK3PXP",
            ],
        )
        self.assertNotIn("Aa150010150010", full["content"])

    def test_transfer_content_returns_skip_details_and_preserves_source_rows(self) -> None:
        running = self._row("running@example.test")
        missing = self._row("missing@example.test")
        result = self.pool.build_transfer_content([running.row_id, missing.row_id, "0" * 64])
        self.assertEqual(result["prepared"], 0)
        self.assertEqual(result["skipped"], 3)
        reasons = {item["reason"] for item in result["skipped_items"]}
        self.assertIn("该 Free 邮箱仍在注册或测活任务中", reasons)
        self.assertIn("该 Free 邮箱没有注册结果，暂不可传输", reasons)
        self.assertIn("Free 邮箱行不存在或已变化", reasons)
        self.assertEqual({row.email for row in self.pool.entries()}, {
            "with-password@example.test",
            "with-totp@example.test",
            "passwordless@example.test",
            "passwordless-totp@example.test",
            "running@example.test",
            "missing@example.test",
        })

    def test_transfer_content_never_treats_invalid_selection_as_all_rows(self) -> None:
        result = self.pool.build_transfer_content(["", "  "])

        self.assertEqual(result["selected"], 0)
        self.assertEqual(result["prepared"], 0)
        self.assertEqual(result["content"], "")
        self.assertEqual(result["skipped"], 1)

    def _controller_app(self, importer):
        app = Flask(__name__)
        manager = SimpleNamespace(pool=self.pool)
        controller = FreePoolRouteController(
            module=flask,
            manager=manager,
            config_store=None,
            state=lambda: {"running": False},
            mutation_conflict=lambda _action: None,
            error_response=lambda exc, **_kwargs: (jsonify(ok=False, error=str(exc)), 400),
            failure_response=lambda exc, **_kwargs: (jsonify(ok=False, error=str(exc)), 503),
            request_lock=threading.Lock(),
            ordinary_mailbox_import=importer,
        )
        app.add_url_rule("/transfer", view_func=controller.transfer, methods=["POST"])
        app.add_url_rule("/format", view_func=controller.format, methods=["POST"])
        return app

    def test_transfer_route_reports_duplicate_and_skip_details_without_secrets(self) -> None:
        captured: list[str] = []

        def importer(content: str):
            captured.append(content)
            return {"ok": True, "imported": 1, "skipped": 1}

        app = self._controller_app(importer)
        selected = [self._row("with-password@example.test").row_id, self._row("running@example.test").row_id]
        with app.test_client() as client:
            response = client.post("/transfer", json={"row_ids": selected})
        payload = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["imported"], 1)
        self.assertEqual(payload["skipped"], 2)
        self.assertTrue(any("普通接码邮箱池跳过重复 1 条" in item["reason"] for item in payload["skipped_items"]))
        self.assertEqual(len(captured), 1)
        self.assertNotIn("real-openai-password", str(payload))
        self.assertNotIn("https://mail.example.test/password", str(payload))

    def test_transfer_and_format_reject_empty_normalized_selection(self) -> None:
        called: list[str] = []

        def importer(content: str):
            called.append(content)
            return {"ok": True, "imported": 1, "skipped": 0}

        app = self._controller_app(importer)
        with app.test_client() as client:
            transfer = client.post("/transfer", json={"row_ids": ["", "  "]})
            formatted = client.post("/format", json={"mode": "full", "row_ids": [""]})

        self.assertEqual(transfer.status_code, 400)
        self.assertEqual(formatted.status_code, 400)
        self.assertFalse(called)

    def test_transfer_reports_all_duplicate_rows(self) -> None:
        app = self._controller_app(
            lambda _content: {"ok": False, "error": "没有新增邮箱，可能都是重复行"}
        )
        selected = [
            self._row("with-password@example.test").row_id,
            self._row("with-totp@example.test").row_id,
        ]
        with app.test_client() as client:
            response = client.post("/transfer", json={"row_ids": selected})

        payload = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(payload["imported"], 0)
        self.assertEqual(payload["skipped"], 2)
        self.assertFalse(payload["ordinary_mailboxes_refresh_required"])
        self.assertTrue(any("跳过重复 2 条" in item["reason"] for item in payload["skipped_items"]))

    def test_format_route_returns_skip_details_when_no_row_is_transferable(self) -> None:
        row_id = self._row("running@example.test").row_id
        app = self._controller_app(lambda _content: {"ok": True, "imported": 0, "skipped": 0})
        with app.test_client() as client:
            response = client.post("/format", json={"mode": "full", "row_ids": [row_id]})
        payload = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["prepared"], 0)
        self.assertEqual(payload["skipped"], 1)
        self.assertEqual(payload["content"], "")
        self.assertNotIn("real-openai-password", str(payload))

    def test_temporary_totp_returns_code_and_never_seed(self) -> None:
        manager = object.__new__(FreeRegisterManager)
        manager.pool = self.pool
        manager._tasks = {}
        manager._lock = threading.RLock()
        row = self._row("passwordless-totp@example.test")
        result = manager.temporary_totp(row_ids=[row.row_id])
        self.assertRegex(result["code"], r"^\d{6}$")
        self.assertGreaterEqual(result["remaining"], 1)
        self.assertLessEqual(result["remaining"], 30)
        self.assertNotIn("JBSWY3DPEHPK3PXP", str(result))


if __name__ == "__main__":
    unittest.main()
