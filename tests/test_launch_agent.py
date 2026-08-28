from __future__ import annotations

from pathlib import Path
import unittest


class LaunchAgentScriptTests(unittest.TestCase):
    def test_start_script_generates_background_replaceable_agent(self):
        script = Path(__file__).resolve().parents[1].joinpath("start.command").read_text(encoding="utf-8")
        self.assertIn("launchctl bootout", script)
        self.assertIn("launchctl bootstrap", script)
        self.assertIn("<key>ProcessType</key>", script)
        self.assertIn("<string>Background</string>", script)
        self.assertIn("<key>LSUIElement</key>", script)
        self.assertIn("<key>StandardOutPath</key>", script)
        self.assertIn("<key>StandardErrorPath</key>", script)
        self.assertIn("/usr/bin/lockf -t 0", script)
        self.assertIn("-sTCP:LISTEN", script)
        self.assertIn("kill -9", script)
        self.assertNotIn("/usr/bin/pgrep -f", script)
        self.assertNotIn('exec "$VENV_DIR/bin/python"', script)


if __name__ == "__main__":
    unittest.main()
