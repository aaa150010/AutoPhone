from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import re
from pathlib import Path
import tempfile
import unittest

from app import create_app, import_batch
from security import hash_password, token_hash


class OnlineMailboxServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temp_dir.name) / "mailboxes.db"
        self.web_password = "web-password-private"
        self.api_token = "api-token-private"
        self.app = create_app({
            "TESTING": True,
            "DATABASE_PATH": str(self.database_path),
            "WEB_PASSWORD_HASH": hash_password(self.web_password, iterations=1_000),
            "API_TOKEN_SHA256": token_hash(self.api_token),
            "SECRET_KEY": "session-secret-private",
            "SESSION_COOKIE_SECURE": False,
            "MAX_IMPORT_ITEMS": 100,
        })

    def tearDown(self):
        self.temp_dir.cleanup()

    def _headers(self):
        return {"Authorization": f"Bearer {self.api_token}"}

    def _item(self, url="https://mail.example.test/inbox/one-private"):
        return {"email": "User@Example.TEST", "mailbox_url": url}

    def _login(self, client):
        page = client.get("/token-tool/mailboxes/login")
        csrf = self._csrf(page)
        return client.post(
            "/token-tool/mailboxes/login",
            data={"csrf_token": csrf, "password": self.web_password},
        )

    def _csrf(self, response):
        match = re.search(r'name="csrf_token" value="([^"]+)"', response.get_data(as_text=True))
        self.assertIsNotNone(match)
        return match.group(1)

    def test_health_and_authentication_boundaries(self):
        client = self.app.test_client()
        self.assertEqual(client.get("/token-tool/api/health").status_code, 200)
        self.assertEqual(client.get("/token-tool/api/mailboxes").status_code, 401)
        self.assertEqual(client.get("/token-tool/mailboxes/").status_code, 302)

        login_page = client.get("/token-tool/mailboxes/login")
        self.assertNotIn(self.web_password, login_page.get_data(as_text=True))
        csrf = self._csrf(login_page)
        failed = client.post(
            "/token-tool/mailboxes/login",
            data={"csrf_token": csrf, "password": "wrong"},
        )
        self.assertIn("访问密码不正确", failed.get_data(as_text=True))
        self.assertEqual(self._login(client).status_code, 302)
        self.assertEqual(client.get("/token-tool/mailboxes/").status_code, 200)

    def test_import_requires_bearer_token(self):
        payload = {"batch_id": "batch-auth", "source": "autophone", "items": [self._item()]}
        client = self.app.test_client()

        missing = client.post("/token-tool/api/mailboxes/import", json=payload)
        wrong = client.post(
            "/token-tool/api/mailboxes/import",
            json=payload,
            headers={"Authorization": "Bearer wrong-private"},
        )

        self.assertEqual(missing.status_code, 401)
        self.assertEqual(wrong.status_code, 401)
        self.assertNotIn(self.api_token, missing.get_data(as_text=True))
        self.assertNotIn("wrong-private", wrong.get_data(as_text=True))

    def test_create_idempotency_duplicate_and_url_update_history(self):
        client = self.app.test_client()
        first_payload = {"batch_id": "batch-one", "source": "autophone", "items": [self._item()]}

        created = client.post(
            "/token-tool/api/mailboxes/import",
            json=first_payload,
            headers=self._headers(),
        )
        replayed = client.post(
            "/token-tool/api/mailboxes/import",
            json=first_payload,
            headers=self._headers(),
        )
        duplicate = client.post(
            "/token-tool/api/mailboxes/import",
            json={"batch_id": "batch-two", "source": "autophone", "items": [self._item()]},
            headers=self._headers(),
        )
        new_url = "https://mail.example.test/inbox/two-private"
        updated = client.post(
            "/token-tool/api/mailboxes/import",
            json={"batch_id": "batch-three", "source": "autophone", "items": [self._item(new_url)]},
            headers=self._headers(),
        )

        self.assertEqual(created.get_json()["created"], 1)
        self.assertTrue(replayed.get_json()["idempotent"])
        self.assertEqual(duplicate.get_json()["duplicates"], 1)
        self.assertEqual(updated.get_json()["updated"], 1)
        self._login(client)
        mailboxes = client.get("/token-tool/api/mailboxes").get_json()
        self.assertEqual(mailboxes["total"], 1)
        self.assertEqual(mailboxes["items"][0]["mailbox_url"], new_url)
        self.assertEqual(mailboxes["items"][0]["upload_count"], 3)
        uploads = client.get("/token-tool/api/uploads").get_json()
        self.assertEqual(uploads["total"], 3)
        self.assertEqual(
            {item["action"] for item in uploads["items"]},
            {"created", "duplicate", "updated"},
        )

    def test_same_batch_with_different_payload_conflicts(self):
        client = self.app.test_client()
        first = {"batch_id": "batch-conflict", "source": "autophone", "items": [self._item()]}
        second = {
            "batch_id": "batch-conflict",
            "source": "autophone",
            "items": [self._item("https://mail.example.test/inbox/different-private")],
        }

        self.assertEqual(client.post(
            "/token-tool/api/mailboxes/import", json=first, headers=self._headers()
        ).status_code, 200)
        conflict = client.post(
            "/token-tool/api/mailboxes/import", json=second, headers=self._headers()
        )
        self.assertEqual(conflict.status_code, 409)

    def test_invalid_rows_are_rejected_without_persisting_values(self):
        invalid_secret = "javascript:private-secret"
        client = self.app.test_client()
        response = client.post(
            "/token-tool/api/mailboxes/import",
            json={
                "batch_id": "batch-rejected",
                "source": "autophone",
                "items": [self._item(), {"email": "bad", "mailbox_url": invalid_secret}],
            },
            headers=self._headers(),
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["rejected"], 1)
        self.assertNotIn(invalid_secret, response.get_data(as_text=True))

    def test_concurrent_batches_keep_one_unique_mailbox(self):
        def upload(index):
            return import_batch(
                self.app,
                batch_id=f"parallel-{index}",
                source="autophone",
                raw_items=[self._item()],
            )

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(upload, range(2)))

        self.assertEqual(sum(result["created"] for result in results), 1)
        self.assertEqual(sum(result["duplicates"] for result in results), 1)
        client = self.app.test_client()
        self._login(client)
        self.assertEqual(client.get("/token-tool/api/mailboxes").get_json()["total"], 1)

    def test_login_rate_limit_and_csrf(self):
        client = self.app.test_client()
        login_page = client.get("/token-tool/mailboxes/login")
        csrf = self._csrf(login_page)
        no_csrf = client.post(
            "/token-tool/mailboxes/login",
            data={"password": self.web_password},
        )
        self.assertIn("页面已失效", no_csrf.get_data(as_text=True))
        for _index in range(5):
            client.post(
                "/token-tool/mailboxes/login",
                data={"csrf_token": csrf, "password": "wrong"},
            )
        blocked = client.post(
            "/token-tool/mailboxes/login",
            data={"csrf_token": csrf, "password": self.web_password},
        )
        self.assertIn("登录尝试过多", blocked.get_data(as_text=True))


if __name__ == "__main__":
    unittest.main()
