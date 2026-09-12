"""Contract tests for Camoufox browser-pool auto sizing."""

from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

try:
    from mac_overrides.free_camoufox.pool_sizing import derive_camoufox_pool_sizing
    from mac_overrides.free_register_runtime import FreeRegisterManager
except ImportError:
    from free_camoufox.pool_sizing import derive_camoufox_pool_sizing  # type: ignore[no-redef]
    from free_register_runtime import FreeRegisterManager  # type: ignore[no-redef]


def _config(**overrides):
    base = {
        "driver": "camoufox",
        "concurrency": 4,
        "target_count": 4,
        "camoufox": {
            "pool_size": 2,
            "max_contexts_per_browser": 3,
            "camoufox_pool_auto": True,
        },
    }
    base.update(overrides)
    return base


class DeriveCamoufoxPoolSizingTests(unittest.TestCase):
    def test_table_driven_sizing_matches_capacity_rules(self) -> None:
        cases = {
            1: (1, 3),
            2: (1, 3),
            4: (2, 3),
            6: (3, 3),
            7: (2, 4),
            8: (3, 4),
            12: (4, 4),
            16: (4, 4),
        }
        for workers, expected in cases.items():
            with self.subTest(workers=workers):
                sizing = derive_camoufox_pool_sizing(_config(concurrency=workers, target_count=workers))
                self.assertIsNotNone(sizing)
                self.assertEqual(sizing.workers, workers)
                self.assertEqual((sizing.pool_size, sizing.max_contexts), expected)
                self.assertGreaterEqual(sizing.capacity, workers)

    def test_workers_follow_the_real_executor_width(self) -> None:
        # workers = min(concurrency, target_count, 16), mirroring startup.
        sizing = derive_camoufox_pool_sizing(_config(concurrency=8, target_count=1))
        self.assertEqual(sizing.workers, 1)
        sizing = derive_camoufox_pool_sizing(_config(concurrency=99, target_count=99))
        self.assertEqual(sizing.workers, 16)

    def test_auto_off_returns_none_and_keeps_manual_values(self) -> None:
        config = _config(camoufox={
            "pool_size": 5,
            "max_contexts_per_browser": 7,
            "camoufox_pool_auto": False,
        })
        self.assertIsNone(derive_camoufox_pool_sizing(config))

    def test_non_camoufox_driver_returns_none(self) -> None:
        self.assertIsNone(derive_camoufox_pool_sizing(_config(driver="protocol")))

    def test_missing_camoufox_block_defaults_to_auto(self) -> None:
        sizing = derive_camoufox_pool_sizing({"driver": "camoufox", "concurrency": 4, "target_count": 4})
        self.assertIsNotNone(sizing)
        self.assertEqual((sizing.pool_size, sizing.max_contexts), (2, 3))


class StartInjectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.data_dir = Path(self._tmp.name)

    def _start_capture(self, config: dict) -> dict:
        manager = FreeRegisterManager(self.data_dir)
        with patch.object(manager, "_start_locked", return_value={}) as locked:
            manager.start(config)
        return locked.call_args[0][0]

    def test_start_injects_derived_pool_sizing(self) -> None:
        captured = self._start_capture(_config(concurrency=8, target_count=8))
        self.assertEqual(captured["camoufox"]["pool_size"], 3)
        self.assertEqual(captured["camoufox"]["max_contexts_per_browser"], 4)

    def test_start_keeps_manual_values_when_auto_off(self) -> None:
        config = _config(camoufox={
            "pool_size": 5,
            "max_contexts_per_browser": 7,
            "camoufox_pool_auto": False,
        })
        captured = self._start_capture(config)
        self.assertEqual(captured["camoufox"]["pool_size"], 5)
        self.assertEqual(captured["camoufox"]["max_contexts_per_browser"], 7)

    def test_start_leaves_protocol_driver_untouched(self) -> None:
        captured = self._start_capture(_config(driver="protocol"))
        self.assertEqual(captured["camoufox"]["pool_size"], 2)
        self.assertEqual(captured["camoufox"]["max_contexts_per_browser"], 3)


if __name__ == "__main__":
    unittest.main()
