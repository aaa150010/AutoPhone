from __future__ import annotations

from dataclasses import dataclass
import inspect
import unittest

from mac_overrides.sms_runtime import _candidate_value, _route_stat
from mac_overrides.sms_route_runtime import has_better_mature_alternative


@dataclass
class _Candidate:
    country: str
    provider_id: str
    score: float = 1.0
    price: float = 0.04
    count: int = 10


class SmsRouteRuntimeTests(unittest.TestCase):
    def test_sms_runtime_keeps_extracted_helper_signatures_and_behavior(self):
        candidate_parameters = tuple(inspect.signature(_candidate_value).parameters)
        route_parameters = tuple(inspect.signature(_route_stat).parameters)

        self.assertEqual(candidate_parameters, ("candidate", "name", "default"))
        self.assertEqual(route_parameters, ("route_stats", "route"))
        self.assertEqual(_candidate_value({"score": 7}, "score", 0), 7)
        self.assertEqual(
            _route_stat({"1::route": {"success": 2}}, ("1", "route")),
            {"success": 2},
        )

    def test_mature_alternative_must_rank_above_current_route(self):
        current = _Candidate("1", "current", score=10.0)
        mature_but_lower = _Candidate("2", "alternative", score=1.0)
        route_stats = {
            ("1", "current"): {"timeout": 3, "no_code_streak": 2},
            ("2", "alternative"): {"otp_received": 8, "timeout": 2},
        }
        country_stats = {
            "1": {"success": 9, "fail": 1},
            "2": {"success": 0, "fail": 10},
        }

        self.assertFalse(
            has_better_mature_alternative(
                current,
                [current, mature_but_lower],
                route_stats,
                country_stats=country_stats,
                now=1000,
            )
        )

    def test_mature_alternative_can_switch_when_full_ranking_is_higher(self):
        current = _Candidate("1", "current", score=10.0)
        better = _Candidate("2", "alternative", score=1.0)
        route_stats = {
            ("1", "current"): {"timeout": 3, "no_code_streak": 2},
            ("2", "alternative"): {"otp_received": 8, "timeout": 2},
        }
        country_stats = {
            "1": {"success": 0, "fail": 10},
            "2": {"success": 9, "fail": 1},
        }

        self.assertTrue(
            has_better_mature_alternative(
                current,
                [current, better],
                route_stats,
                country_stats=country_stats,
                now=1000,
            )
        )


if __name__ == "__main__":
    unittest.main()
