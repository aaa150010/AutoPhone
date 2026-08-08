"""SMS route quality, ranking, and adaptive wait decisions."""

from __future__ import annotations

from dataclasses import dataclass
import math
from threading import Lock
import time
from typing import Any, Callable


def _as_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return float(default)


def _candidate_value(candidate: Any, name: str, default: Any = None) -> Any:
    if isinstance(candidate, dict):
        return candidate.get(name, default)
    return getattr(candidate, name, default)


def candidate_route(candidate: Any) -> tuple[str, str]:
    """Return the recovered selector's persisted route identity."""
    return (
        str(_candidate_value(candidate, "country", "") or ""),
        str(_candidate_value(candidate, "provider_id", "") or ""),
    )


def route_stat(route_stats: Any, route: tuple[str, str]) -> dict[str, Any]:
    if not isinstance(route_stats, dict):
        return {}
    value = route_stats.get(route)
    if not isinstance(value, dict):
        value = route_stats.get("::".join(route))
    return value if isinstance(value, dict) else {}


def wilson_lower_bound(successes: Any, observations: Any, z: float = 1.959963984540054) -> float:
    """Return the lower bound of a 95% Wilson score interval."""
    total = max(0, int(_as_float(observations, 0)))
    passed = min(total, max(0, int(_as_float(successes, 0))))
    if total <= 0:
        return 0.0
    rate = passed / total
    z_squared = float(z) ** 2
    denominator = 1.0 + z_squared / total
    centre = rate + z_squared / (2.0 * total)
    margin = float(z) * math.sqrt(
        (rate * (1.0 - rate) + z_squared / (4.0 * total)) / total
    )
    return max(0.0, (centre - margin) / denominator)


@dataclass(frozen=True)
class DeliveryQuality:
    successes: int
    failures: int
    observations: int
    rate: float
    lower_bound: float
    mature: bool


@dataclass(frozen=True)
class SmsWaitPlan:
    first_seconds: int = 30
    second_seconds: int = 30
    early_switch: bool = False
    degraded: bool = False


def delivery_quality(stat: Any, *, minimum_observations: int = 5) -> DeliveryQuality:
    row = stat if isinstance(stat, dict) else {}
    successes = max(0, int(_as_float(row.get("otp_received"), 0)))
    failures = max(
        max(0, int(_as_float(row.get("timeout"), 0))),
        max(0, int(_as_float(row.get("otp_sent"), 0))),
    )
    observations = successes + failures
    rate = successes / observations if observations else 0.0
    return DeliveryQuality(
        successes=successes,
        failures=failures,
        observations=observations,
        rate=rate,
        lower_bound=wilson_lower_bound(successes, observations),
        mature=observations >= max(1, int(minimum_observations)),
    )


def is_degraded_route(stat: Any) -> bool:
    row = stat if isinstance(stat, dict) else {}
    quality = delivery_quality(row)
    no_code_streak = max(0, int(_as_float(row.get("no_code_streak"), 0)))
    timeout_count = max(
        max(0, int(_as_float(row.get("timeout"), 0))),
        quality.failures,
    )
    return no_code_streak >= 2 or (timeout_count >= 3 and quality.rate < 0.35)


def is_mature_delivery_route(stat: Any, *, minimum_rate: float = 0.60) -> bool:
    quality = delivery_quality(stat)
    return quality.mature and quality.rate >= float(minimum_rate)


def has_better_mature_alternative(
    current_candidate: Any,
    candidates: Any,
    route_stats: Any,
    *,
    country_stats: Any = None,
    priority_routes: tuple[tuple[str, ...], ...] = (),
    priority_countries: tuple[str, ...] = (),
    now: float | None = None,
    minimum_rate: float = 0.60,
    reliability_mode: bool = False,
    quality_optimization: bool = True,
) -> bool:
    current_route = candidate_route(current_candidate)
    current = time.time() if now is None else float(now)
    available = list(candidates or ())
    if not any(candidate_route(candidate) == current_route for candidate in available):
        available.append(current_candidate)
    ranked = rank_sms_candidates(
        available,
        route_stats,
        country_stats=country_stats,
        priority_routes=priority_routes,
        priority_countries=priority_countries,
        now=current,
        reliability_mode=reliability_mode,
        quality_optimization=quality_optimization,
    )
    current_index = next(
        (
            index
            for index, candidate in enumerate(ranked)
            if candidate_route(candidate) == current_route
        ),
        0,
    )
    for candidate in ranked[:current_index]:
        route = candidate_route(candidate)
        if not all(route) or route == current_route:
            continue
        stat = route_stat(route_stats, route)
        if _as_float(stat.get("cooldown_until"), 0.0) > current:
            continue
        quality = delivery_quality(stat)
        if not quality.mature or quality.rate < float(minimum_rate):
            continue
        return True
    return False


def build_sms_wait_plan(
    stat: Any,
    *,
    optimization_enabled: bool = True,
    better_mature_alternative: bool = False,
) -> SmsWaitPlan:
    if not optimization_enabled or not is_degraded_route(stat):
        return SmsWaitPlan()
    return SmsWaitPlan(
        first_seconds=40,
        second_seconds=20,
        early_switch=bool(better_mature_alternative),
        degraded=True,
    )


def _route_metrics(
    candidate: Any,
    route_stats: Any,
    *,
    current: float,
    recent_window: float,
    route_priority: dict[tuple[str, ...], int],
) -> dict[str, Any]:
    route = candidate_route(candidate)
    legacy_route = route[-2:]
    stat = route_stat(route_stats, route)
    if not stat and route != legacy_route:
        stat = route_stat(route_stats, legacy_route)
    final_success = max(0, int(_as_float(stat.get("success"), 0)))
    otp_received = max(0, int(_as_float(stat.get("otp_received"), 0)))
    failures = max(0, int(_as_float(stat.get("fail"), 0)))
    no_numbers = max(0, int(_as_float(stat.get("no_numbers"), 0)))
    classified_failures = sum(
        max(0, int(_as_float(stat.get(name), 0)))
        for name in ("phone_rejected", "register_rejected", "invalid_auth_step", "timeout")
    )
    rejected = max(0, failures - no_numbers, classified_failures)
    acceptance_success = max(final_success, otp_received)
    quality_observations = acceptance_success + rejected
    legacy_observations = quality_observations + no_numbers
    acceptance_rate = (
        acceptance_success / quality_observations if quality_observations else 0.0
    )
    final_attempts = final_success + rejected
    final_success_rate = final_success / final_attempts if final_attempts else 0.0
    delivery = delivery_quality(stat)
    last_success_at = max(
        _as_float(stat.get("last_success_at"), 0.0),
        _as_float(stat.get("last_delivery_at"), 0.0),
    )
    recently_successful = bool(
        last_success_at > 0
        and recent_window > 0
        and 0 <= current - last_success_at <= recent_window
    )
    return {
        "route": route,
        "legacy_route": legacy_route,
        "final_success": final_success,
        "otp_received": otp_received,
        "no_numbers": no_numbers,
        "acceptance_success": acceptance_success,
        "quality_observations": quality_observations,
        "legacy_observations": legacy_observations,
        "acceptance_rate": acceptance_rate,
        "acceptance_lower_bound": wilson_lower_bound(
            acceptance_success, quality_observations
        ),
        "final_success_rate": final_success_rate,
        "delivery_rate": delivery.rate,
        "delivery_lower_bound": delivery.lower_bound,
        "delivery_mature": delivery.mature,
        "last_success_at": last_success_at,
        "recently_successful": recently_successful,
        "preferred": route in route_priority or legacy_route in route_priority,
    }


def _country_metrics(country: str, country_stats: Any) -> dict[str, Any]:
    row = country_stats.get(country) if isinstance(country_stats, dict) else None
    stat = row if isinstance(row, dict) else {}
    successes = max(0, int(_as_float(stat.get("success"), 0)))
    # The recovered selector records no_numbers separately and deliberately
    # does not increment country fail for that inventory-only outcome.
    failures = max(
        max(0, int(_as_float(stat.get("fail"), 0))),
        sum(
            max(0, int(_as_float(stat.get(name), 0)))
            for name in (
                "phone_rejected",
                "register_rejected",
                "register_rate_limited",
                "invalid_auth_step",
                "timeout",
            )
        ),
    )
    observations = successes + failures
    return {
        "successes": successes,
        "observations": observations,
        "lower_bound": wilson_lower_bound(successes, observations),
        "mature": observations >= 5,
    }


def rank_sms_candidates(
    candidates: list[Any],
    route_stats: Any,
    *,
    country_stats: Any = None,
    priority_routes: tuple[tuple[str, ...], ...] = (),
    priority_countries: tuple[str, ...] = (),
    minimum_proven_rate: float = 0.10,
    now: float | None = None,
    recent_success_window_seconds: float = 600.0,
    reliability_mode: bool = False,
    quality_optimization: bool = True,
) -> list[Any]:
    """Rank by proven country and delivery quality, with price as a tie-breaker."""
    route_priority = {route: index for index, route in enumerate(priority_routes)}
    country_priority = {country: index for index, country in enumerate(priority_countries)}
    default_route_priority = len(route_priority)
    default_country_priority = len(country_priority)
    current = time.time() if now is None else float(now)
    recent_window = max(0.0, float(recent_success_window_seconds))

    def metrics(candidate: Any) -> dict[str, Any]:
        return _route_metrics(
            candidate,
            route_stats,
            current=current,
            recent_window=recent_window,
            route_priority=route_priority,
        )

    def legacy_normal_key(candidate: Any) -> tuple[Any, ...]:
        values = metrics(candidate)
        route = values["route"]
        legacy_route = values["legacy_route"]
        success = values["acceptance_success"]
        observations = values["legacy_observations"]
        legacy_rate = success / observations if observations else 0.0
        if success > 0 and legacy_rate >= minimum_proven_rate:
            tier = 0
        elif observations == 0 and values["preferred"]:
            tier = 1
        elif success > 0:
            tier = 2
        elif observations == 0:
            tier = 3
        else:
            tier = 4
        return (
            tier,
            not values["recently_successful"],
            -legacy_rate,
            -success,
            route_priority.get(
                route, route_priority.get(legacy_route, default_route_priority)
            ),
            country_priority.get(route[0], default_country_priority),
            -_as_float(_candidate_value(candidate, "score", 0.0), 0.0),
            _as_float(_candidate_value(candidate, "price", 999.0), 999.0),
            -int(_as_float(_candidate_value(candidate, "count", 0), 0)),
        )

    if reliability_mode:
        has_mature_risk_route = any(
            (lambda values: (
                values["final_success"] > 0
                and values["final_success_rate"] >= minimum_proven_rate
            ))(metrics(candidate))
            for candidate in candidates
        )
        if not has_mature_risk_route:
            return rank_sms_candidates(
                candidates,
                route_stats,
                country_stats=country_stats,
                priority_routes=priority_routes,
                priority_countries=priority_countries,
                minimum_proven_rate=minimum_proven_rate,
                now=current,
                recent_success_window_seconds=recent_window,
                reliability_mode=False,
                quality_optimization=quality_optimization,
            )

        def reliability_key(candidate: Any) -> tuple[Any, ...]:
            values = metrics(candidate)
            qualified = (
                values["final_success"] > 0
                and values["final_success_rate"] >= minimum_proven_rate
            )
            if values["otp_received"] > 0 and qualified:
                tier = 0
            elif values["otp_received"] == 0 and qualified:
                tier = 1
            else:
                return (2, *legacy_normal_key(candidate))
            return (
                tier,
                not values["recently_successful"],
                -values["last_success_at"],
                -values["delivery_rate"],
                -values["final_success_rate"],
                -values["final_success"],
                _as_float(_candidate_value(candidate, "price", 999.0), 999.0),
                -int(_as_float(_candidate_value(candidate, "count", 0), 0)),
            )

        return sorted(candidates, key=reliability_key)

    if not quality_optimization:
        return sorted(candidates, key=legacy_normal_key)

    def quality_key(candidate: Any) -> tuple[Any, ...]:
        values = metrics(candidate)
        route = values["route"]
        legacy_route = values["legacy_route"]
        country = _country_metrics(route[0], country_stats)
        if country["mature"] and country["successes"] > 0:
            country_tier = 0
        elif not country["mature"]:
            country_tier = 1
        else:
            country_tier = 2

        success = values["acceptance_success"]
        observations = values["quality_observations"]
        if observations >= 5 and success > 0:
            route_tier = 0
        elif observations < 5:
            route_tier = 1
        else:
            route_tier = 2

        return (
            country_tier,
            -country["lower_bound"],
            bool(values["no_numbers"] and not success),
            route_tier,
            not values["recently_successful"],
            -values["delivery_lower_bound"],
            -values["acceptance_lower_bound"],
            -_as_float(_candidate_value(candidate, "score", 0.0), 0.0),
            route_priority.get(
                route, route_priority.get(legacy_route, default_route_priority)
            ),
            country_priority.get(route[0], default_country_priority),
            -int(_as_float(_candidate_value(candidate, "count", 0), 0)),
            _as_float(_candidate_value(candidate, "price", 999.0), 999.0),
        )

    return sorted(candidates, key=quality_key)


class SmsRoutePolicy:
    """Keeps unavailable and non-delivering routes away from concurrent workers."""

    def __init__(
        self,
        *,
        now_fn: Callable[[], float] = time.time,
        streak_window_seconds: float = 1800.0,
    ) -> None:
        self.lock = Lock()
        self.now_fn = now_fn
        self.streak_window_seconds = max(0.0, float(streak_window_seconds))
        self.no_code_streaks: dict[tuple[str, ...], int] = {}

    @staticmethod
    def key(candidate: Any) -> tuple[str, ...]:
        return candidate_route(candidate)

    @staticmethod
    def route_limit(stat: Any) -> int:
        row = stat if isinstance(stat, dict) else {}
        proven = any(
            int(_as_float(row.get(name), 0)) > 0
            for name in ("otp_received", "success")
        )
        return 2 if proven else 1

    def reset(self) -> None:
        with self.lock:
            self.no_code_streaks.clear()

    def update_stat_for_outcome(
        self,
        stat: Any,
        *,
        ok: bool,
        kind: str,
        now: float | None = None,
    ) -> dict[str, Any]:
        row = dict(stat or {}) if isinstance(stat, dict) else {}
        current = self.now_fn() if now is None else float(now)
        if ok:
            for streak_name, timestamp_name in (
                ("no_numbers_streak", "last_no_numbers_at"),
                ("no_code_streak", "last_no_code_at"),
                ("generic_failure_streak", "last_generic_failure_at"),
            ):
                failure_at = _as_float(row.get(timestamp_name), 0.0)
                if timestamp_name not in row or failure_at <= current:
                    row.pop(streak_name, None)
                    row.pop(timestamp_name, None)
            return row

        latest_success_at = max(
            _as_float(row.get("last_success_at"), 0.0),
            _as_float(row.get("last_delivery_at"), 0.0),
        )
        if latest_success_at > current:
            return row

        def record_failure(streak_name: str, timestamp_name: str) -> dict[str, Any]:
            has_previous = timestamp_name in row
            previous_at = _as_float(row.get(timestamp_name), 0.0)
            delta = current - previous_at
            if has_previous and delta < -self.streak_window_seconds:
                return row
            within_window = bool(
                has_previous
                and self.streak_window_seconds > 0
                and abs(delta) <= self.streak_window_seconds
            )
            previous = max(0, int(_as_float(row.get(streak_name), 0)))
            row[streak_name] = previous + 1 if within_window else 1
            row[timestamp_name] = max(previous_at, current) if has_previous else current
            return row

        if kind == "no_numbers":
            return record_failure("no_numbers_streak", "last_no_numbers_at")
        if kind in {"timeout", "no_code"}:
            return record_failure("no_code_streak", "last_no_code_at")
        return record_failure("generic_failure_streak", "last_generic_failure_at")

    def record_delivery(self, stat: Any, *, now: float | None = None) -> dict[str, Any]:
        current = self.now_fn() if now is None else float(now)
        row = self.update_stat_for_outcome(stat, ok=True, kind="success", now=current)
        row["otp_received"] = max(0, int(_as_float(row.get("otp_received"), 0))) + 1
        row["last_delivery_at"] = max(
            _as_float(row.get("last_delivery_at"), 0.0), current
        )
        row["last_kind"] = "otp_received"
        row.pop("cooldown_until", None)
        return row

    def cooldown_for(
        self,
        candidate: Any,
        *,
        ok: bool,
        kind: str,
        error: Any = "",
        stat: Any = None,
    ) -> int:
        route = self.key(candidate)
        text = str(error or "").lower()
        if not all(route):
            return 0
        with self.lock:
            if ok or kind == "transient_server":
                return 0
            if kind == "no_numbers":
                row = stat if isinstance(stat, dict) else {}
                streak = max(1, int(_as_float(row.get("no_numbers_streak"), 1)))
                return 180 if streak >= 3 else 60
            if kind in {"timeout", "no_code"}:
                return 180
            if kind in {"invalid_auth_step", "auth_session", "auth_context"}:
                return 600
            if kind in {"unsupported", "unsupported_route"} or any(
                marker in text for marker in ("unsupported", "not supported")
            ):
                return 900
            if any(
                marker in text
                for marker in (
                    "similar",
                    "suspicious",
                    "try another number",
                    "too many accounts",
                )
            ):
                return 180
            if kind == "phone_rejected" or any(
                marker in text
                for marker in ("already been used", "number is already used", "used too many times")
            ):
                return 180
            row = stat if isinstance(stat, dict) else {}
            if int(_as_float(row.get("generic_failure_streak"), 0)) >= 3:
                return 180
            return 0
