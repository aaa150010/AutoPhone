from __future__ import annotations

from types import SimpleNamespace
import unittest

from flask import Flask, jsonify, request

from mac_overrides.free_account_routes import FreeAccountRouteController


class FreeLiveRouteTests(unittest.TestCase):
    def test_live_check_routes_keep_mode_and_rows_inside_free_manager(self):
        calls = []

        class LiveChecks:
            def enqueue(self, row_ids, mode):
                calls.append((list(row_ids), mode))
                return {
                    "accepted": [{"task_id": "free-live-fast-1"}],
                    "accepted_count": 1,
                    "skipped": [],
                    "skipped_count": 0,
                    "state": self.public_state(),
                }

            def public_state(self):
                return {"running": True, "workers": 3, "active": 1, "jobs": []}

        pool = SimpleNamespace(public_rows=lambda: [{"row_id": "free-row-a", "live_check_status": "queued"}])
        manager = SimpleNamespace(pool=pool, live_checks=LiveChecks())
        app = Flask(__name__)
        module = SimpleNamespace(jsonify=jsonify, request=request)

        def error_response(exc, **_kwargs):
            return jsonify(ok=False, error=str(exc)), 400

        controller = FreeAccountRouteController(
            module=module,
            manager=manager,
            config_store=None,
            free_state=lambda: {},
            error_response=error_response,
        )
        app.add_url_rule("/api/free/live-check", view_func=controller.live_check, methods=["POST"])
        app.add_url_rule("/api/free/live-check/state", view_func=controller.live_check_state, methods=["GET"])

        with app.test_client() as client:
            started = client.post(
                "/api/free/live-check",
                json={"mode": "fast", "row_ids": ["free-row-a"]},
            )
            state = client.get("/api/free/live-check/state")

        self.assertEqual(started.status_code, 200)
        self.assertEqual(started.get_json()["accepted_count"], 1)
        self.assertEqual(started.get_json()["rows"][0]["row_id"], "free-row-a")
        self.assertEqual(state.status_code, 200)
        self.assertEqual(state.get_json()["state"]["workers"], 3)
        self.assertEqual(calls, [(["free-row-a"], "fast")])


if __name__ == "__main__":
    unittest.main()
