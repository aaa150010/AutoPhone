"""Balance-query orchestration shared by SMS key pools and registries."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable


def query_key_pool_balances(
    pool: Any,
    *,
    proxy: str = "",
    update_state: bool = True,
    parse_balance: Callable[[Any], float],
    max_workers: int,
) -> list[dict[str, Any]]:
    """Query every key, optionally committing the health snapshot.

    A read-only query builds public rows from the observed response while
    leaving generation, revision, cooldown, and status fields untouched.
    """
    with pool.lock:
        states = list(pool.states)
        if update_state:
            pool.preflight_generation += 1
            generation = pool.preflight_generation
            revisions = {id(state): state.health_revision for state in states}
        else:
            generation = 0
            revisions = {}
        minimum_balance = pool.min_price
    if not states:
        return []

    observed_rows: list[dict[str, Any]] = []

    def check_balance(state: Any):
        revision = revisions.get(id(state), 0)
        now = pool.now_fn()
        try:
            provider = pool.provider_factory(state.key, proxy=proxy)
            balance = parse_balance(provider.balance())
        except Exception as exc:
            return state, revision, now, None, exc
        return state, revision, now, balance, None

    workers = min(max_workers, len(states))
    if workers == 1:
        results = [check_balance(states[0])]
    else:
        with ThreadPoolExecutor(
            max_workers=workers,
            thread_name_prefix="sms-balance",
        ) as executor:
            results = list(executor.map(check_balance, states))

    for state, revision, now, balance, error in results:
        if error is not None:
            if update_state:
                pool._mark_error(
                    state,
                    error,
                    runtime=False,
                    expected_revision=revision,
                    expected_generation=generation,
                )
            continue
        if not update_state:
            assert balance is not None
            observed = state.public(now)
            observed["balance_usd"] = round(float(balance), 4)
            observed["status"] = (
                "insufficient_balance"
                if balance + 1e-9 < minimum_balance
                else "usable"
            )
            observed["message"] = (
                "余额低于配置最低价格 $" + f"{minimum_balance:.4f}"
                if observed["status"] == "insufficient_balance"
                else "余额查询成功"
            )
            observed["retry_after_seconds"] = 0
            observed["last_checked_at"] = int(now or 0)
            observed_rows.append(observed)
            continue
        with pool.lock:
            if pool.preflight_generation != generation:
                continue
            if state.health_revision != revision:
                continue
            assert balance is not None
            state.health_revision += 1
            state.balance_usd = balance
            state.last_checked_at = now
            state.cooldown_until = 0.0
            if balance + 1e-9 < minimum_balance:
                state.status = "insufficient_balance"
                state.message = f"余额低于配置最低价格 ${minimum_balance:.4f}"
            else:
                state.status = "usable"
                state.message = "余额查询成功"
    return pool.public_statuses() if update_state else observed_rows


def query_registry_balances(
    registry: Any,
    *,
    proxy: str = "",
    update_state: bool = True,
    max_workers: int,
) -> list[dict[str, Any]]:
    """Query each configured provider pool without inventory discovery."""
    with registry.lock:
        specs = [
            dict(spec)
            for spec in registry.specs
            if registry.pools.get(str(spec.get("provider"))) is not None
            and registry.pools[str(spec.get("provider"))].has_keys()
        ]
    if not specs:
        return []

    def check(spec: dict[str, Any]):
        provider = str(spec.get("provider") or "")
        return spec, registry.pools[provider].query_balances(
            proxy=proxy,
            update_state=update_state,
        )

    workers = min(max_workers, len(specs))
    if workers == 1:
        results = [check(specs[0])]
    else:
        with ThreadPoolExecutor(
            max_workers=workers,
            thread_name_prefix="sms-platform-balance",
        ) as executor:
            results = list(executor.map(check, specs))

    rows: list[dict[str, Any]] = []
    for spec, statuses in results:
        provider = str(spec.get("provider") or "")
        for status in statuses:
            rows.append(
                {
                    **status,
                    "provider": provider,
                    "platform": provider,
                    "service": str(spec.get("service") or "dr"),
                    "enabled": bool(spec.get("enabled", True)),
                }
            )
    return rows


__all__ = ["query_key_pool_balances", "query_registry_balances"]
