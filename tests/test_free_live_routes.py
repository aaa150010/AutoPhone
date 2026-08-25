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

    def test_plan_check_route_enqueues_only_saved_token_rows(self):
        calls = []

        class PlanChecks:
            def enqueue(self, row_ids):
                calls.append(list(row_ids))
                return {"accepted": [{"task_id": "free-plan-1"}], "accepted_count": 1, "skipped": [], "skipped_count": 0, "state": self.public_state(), "rows": [{"row_id": "free-row-a"}]}

            def public_state(self):
                return {"running": True, "workers": 2, "active": 1, "jobs": []}

        pool = SimpleNamespace(public_rows=lambda: [{"row_id": "free-row-a"}])
        manager = SimpleNamespace(pool=pool, plan_checks=PlanChecks())
        app = Flask(__name__)
        module = SimpleNamespace(jsonify=jsonify, request=request)

        def error_response(exc, **_kwargs):
            return jsonify(ok=False, error=str(exc)), 400

        controller = FreeAccountRouteController(
            module=module, manager=manager, config_store=None, free_state=lambda: {}, error_response=error_response,
        )
        app.add_url_rule("/api/free/plan-check", view_func=controller.plan_check, methods=["POST"])
        app.add_url_rule("/api/free/plan-check/state", view_func=controller.plan_check_state, methods=["GET"])
        with app.test_client() as client:
            started = client.post("/api/free/plan-check", json={"row_ids": ["free-row-a"]})
            state = client.get("/api/free/plan-check/state")
        self.assertEqual(started.status_code, 200)
        self.assertEqual(started.get_json()["accepted_count"], 1)
        self.assertEqual(state.get_json()["state"]["workers"], 2)
        self.assertEqual(calls, [["free-row-a"]])


if __name__ == "__main__":
    unittest.main()
