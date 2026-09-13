"""Contract tests for the credential-tunnel minting and target maintenance."""

from __future__ import annotations

from tempfile import TemporaryDirectory
import unittest

try:
    from mac_overrides.free_proxy_store import FreeProxyPool
    from mac_overrides.free_proxy_tunnel import (
        TUNNEL_SOURCE_LABEL,
        TunnelTemplate,
        ensure_target,
        resolve_target_size,
        template_from_config,
    )
except ImportError:
    from free_proxy_store import FreeProxyPool
    from free_proxy_tunnel import (
        TUNNEL_SOURCE_LABEL,
        TunnelTemplate,
        ensure_target,
        resolve_target_size,
        template_from_config,
    )


def _template() -> TunnelTemplate:
    return TunnelTemplate(
        gateway_host="us.cliproxy.example.test",
        gateway_port=3010,
        scheme="socks5",
        username_template="atxfl200589-region-JP-sid-{sid}-t-{t}",
        password="3jhc2mr3",
        sticky_minutes=30,
    )


def _config(**overrides):
    base = {
        "proxy_tunnel_enabled": True,
        "proxy_tunnel_gateway_host": "us.cliproxy.example.test",
        "proxy_tunnel_gateway_port": 3010,
        "proxy_tunnel_scheme": "socks5",
        "proxy_tunnel_username_template": "atxfl200589-region-JP-sid-{sid}-t-{t}",
        "proxy_tunnel_password": "3jhc2mr3",
        "proxy_tunnel_sticky_minutes": 30,
        "proxy_pool_target_size": 0,
        "concurrency": 4,
    }
    base.update(overrides)
    return base


class TunnelTemplateTests(unittest.TestCase):
    def test_mint_renders_template_with_fresh_unique_sids(self) -> None:
        template = _template()
        lines = {template.mint_proxy() for _ in range(20)}
        self.assertEqual(len(lines), 20)
        for line in lines:
            self.assertTrue(line.startswith("socks5://"))
            self.assertIn("-sid-", line)
            self.assertIn("-t-30", line)
            self.assertIn("us.cliproxy.example.test:3010", line)

    def test_template_from_config_requires_enabled_and_placeholder(self) -> None:
        self.assertIsNotNone(template_from_config(_config()))
        self.assertIsNone(template_from_config(_config(proxy_tunnel_enabled=False)))
        self.assertIsNone(template_from_config(_config(proxy_tunnel_username_template="static-user")))
        self.assertIsNone(template_from_config(_config(proxy_tunnel_gateway_host="")))
        self.assertIsNone(template_from_config(_config(proxy_tunnel_gateway_port=0)))
        # A malformed field reference must degrade to "no template", never raise.
        self.assertIsNone(template_from_config(_config(proxy_tunnel_username_template="{sid}-{missing}")))

    def test_sticky_minutes_clamped_to_provider_range(self) -> None:
        self.assertEqual(template_from_config(_config(proxy_tunnel_sticky_minutes=1)).sticky_minutes, 5)
        self.assertEqual(template_from_config(_config(proxy_tunnel_sticky_minutes=999)).sticky_minutes, 120)
        self.assertEqual(template_from_config(_config(proxy_tunnel_sticky_minutes=45)).sticky_minutes, 45)

    def test_resolve_target_size_prefers_explicit_and_falls_back_to_concurrency(self) -> None:
        self.assertEqual(resolve_target_size(_config()), 4)
        self.assertEqual(resolve_target_size(_config(proxy_pool_target_size=10)), 10)
        self.assertEqual(resolve_target_size(_config(concurrency=99, proxy_pool_target_size=0)), 16)
        self.assertEqual(resolve_target_size(_config(concurrency="bad")), 0)


class EnsureTargetTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.pool = FreeProxyPool(self._tmp.name)
        self.template = _template()

    def test_mints_only_the_deficit_and_annotates_window(self) -> None:
        self.pool.import_text("http://manual.example.test:8000\n", source_label="manual")
        minted = ensure_target(self.pool, self.template, target=4)
        self.assertEqual(minted, 3)
        self.assertEqual(self.pool.healthy_count(), 4)
        rows = [
            row for row in self.pool.entries()
            if str(row.get("source_label") or "") == TUNNEL_SOURCE_LABEL
        ]
        self.assertEqual(len(rows), 3)
        for row in rows:
            self.assertTrue(row["window_started_at"] > 0)
            self.assertEqual(row["window_expires_at"], row["window_started_at"] + 30 * 60)

    def test_mint_progress_reports_each_replacement(self) -> None:
        """on_progress receives (minted_so_far, deficit) after every mint."""
        self.pool.import_text("http://manual.example.test:8000\n", source_label="manual")
        events: list[tuple[int, int]] = []
        minted = ensure_target(
            self.pool,
            self.template,
            target=4,
            on_progress=lambda done, deficit: events.append((done, deficit)),
        )
        self.assertEqual(minted, 3)
        self.assertEqual([done for done, _ in events], [1, 2, 3])
        self.assertTrue(all(deficit == 3 for _, deficit in events))

    def test_burned_tunnel_rows_are_removed_and_replaced_manual_rows_survive(self) -> None:
        self.pool.import_text("http://manual.example.test:8000\n", source_label="manual")
        ensure_target(self.pool, self.template, target=3)
        manual_row, *tunnel_rows = self.pool.entries()
        self.assertEqual(str(manual_row.get("source_label") or ""), "manual")
        for row in tunnel_rows:
            self.pool.record_challenge_burn(str(row["proxy_id"]))
        minted = ensure_target(self.pool, self.template, target=3)
        self.assertEqual(minted, 2)
        rows = self.pool.entries()
        self.assertEqual(len(rows), 3)
        self.assertTrue(any(str(row.get("source_label") or "") == "manual" for row in rows))
        self.assertTrue(
            all(str(row.get("status") or "") != "burned" for row in rows),
        )

    def test_capacity_cap_bounds_total_tunnel_rows(self) -> None:
        # target=2 -> capacity cap 4; quarantine 2 healthy rows below target
        # so minting is requested while 2 more tunnel rows already exist.
        ensure_target(self.pool, self.template, target=2)
        rows = [row for row in self.pool.entries() if str(row.get("source_label") or "") == TUNNEL_SOURCE_LABEL]
        self.assertEqual(len(rows), 2)
        extra = ensure_target(self.pool, self.template, target=4)
        # deficit 4 (manual none + 2 tunnel? healthy=2) minus capacity 8-2=6 -> mints 2
        self.assertEqual(extra, 2)
        tunnel_total = len([
            row for row in self.pool.entries()
            if str(row.get("source_label") or "") == TUNNEL_SOURCE_LABEL
        ])
        self.assertEqual(tunnel_total, 4)
        # Next call: healthy=4 >= target=4 -> nothing minted.
        self.assertEqual(ensure_target(self.pool, self.template, target=4), 0)

    def test_window_filter_excludes_rows_close_to_expiry(self) -> None:
        ensure_target(self.pool, self.template, target=2)
        row = self.pool.entries()[0]
        started = float(row["window_started_at"])
        self.assertEqual(len(self.pool._eligible(now=started + 60)), 2)
        # Inside the last 10 minutes of the window allocation stops, so a
        # newly bound task can never observe a mid-task exit rotation.
        self.assertEqual(self.pool._eligible(now=started + 30 * 60 - 540), [])
        self.assertEqual(len(self.pool._eligible(now=started + 60)), 2)

    def test_maintainer_replaces_expired_window_rows(self) -> None:
        ensure_target(self.pool, self.template, target=2)
        for row in self.pool.entries():
            self.pool.annotate_window(
                str(row["proxy_id"]), started_at=1000.0, expires_at=2000.0,
            )
        # Real-time allocation excludes the expired windows; the maintainer
        # then refills the deficit with fresh sids.
        self.assertEqual(self.pool.healthy_count(), 0)
        self.assertEqual(ensure_target(self.pool, self.template, target=2), 2)
        self.assertEqual(self.pool.healthy_count(), 2)

    def test_no_template_is_a_noop(self) -> None:
        self.pool.import_text("http://manual.example.test:8000\n", source_label="manual")
        self.assertEqual(ensure_target(self.pool, None, target=4), 0)
        self.assertEqual(len(self.pool.entries()), 1)


if __name__ == "__main__":
    unittest.main()
