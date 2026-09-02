from __future__ import annotations

from pathlib import Path
import unittest


class DevelopmentLauncherTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.script = Path(__file__).resolve().parents[1].joinpath("start.command").read_text(encoding="utf-8")

    def test_starts_flask_and_vite_in_foreground(self):
        self.assertIn("tools/dev_server.py", self.script)
        self.assertIn('PORT="18777"', self.script)
        self.assertIn('DEV_PORT="5173"', self.script)
        self.assertIn("FLASK_PID=$!", self.script)
        self.assertIn("VITE_PID=$!", self.script)
        self.assertIn('"$NPM_BIN" run dev', self.script)
        self.assertIn('wait "$FLASK_PID" "$VITE_PID"', self.script)

    def test_cleans_both_children_on_exit(self):
        self.assertIn("trap cleanup INT TERM EXIT", self.script)
        self.assertIn('kill "$VITE_PID"', self.script)
        self.assertIn('kill "$FLASK_PID"', self.script)

    def test_no_longer_uses_launch_agent_or_production_build(self):
        self.assertNotIn("launchctl bootstrap", self.script)
        self.assertNotIn("run build", self.script)
        self.assertIn("plus_launcher.pyc", self.script)  # retained only for SentinelRunner resource resolution


if __name__ == "__main__":
    unittest.main()
