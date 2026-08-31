from __future__ import annotations

from pathlib import Path
import unittest


class LaunchAgentScriptTests(unittest.TestCase):
    def test_start_script_generates_background_replaceable_agent(self):
        script = Path(__file__).resolve().parents[1].joinpath("start.command").read_text(encoding="utf-8")
        self.assertIn("launchctl bootout", script)
        self.assertIn("launchctl bootstrap", script)
        self.assertLess(script.index("launchctl bootout"), script.index("launchctl bootstrap"))
        self.assertIn('launchctl print "gui/$USER_ID/$LAUNCH_AGENT_LABEL"', script)
        self.assertIn("launch_agent_pids()", script)
        self.assertIn("owned_webui_pids()", script)
        self.assertIn('LAUNCH_AGENT_PIDS="$(launch_agent_pids)"', script)
        self.assertIn('kill -TERM "${OLD_AGENT_PID_ARRAY[@]}"', script)
        self.assertIn("TERM 等待窗口内未退出", script)
        self.assertIn("旧 WebUI LaunchAgent 在等待窗口内未退出", script)
        self.assertIn("旧 WebUI 进程未能退出", script)
        self.assertIn("is_owned_webui_pid()", script)
        self.assertIn("owned_port_pids()", script)
        self.assertIn('"$APP_DIR/plus_launcher.pyc"', script)
        self.assertIn('"--port $PORT"', script)
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

    def test_old_launch_agent_pid_is_terminated_and_waited_before_bootstrap(self):
        script = Path(__file__).resolve().parents[1].joinpath("start.command").read_text(encoding="utf-8")
        capture = script.index('LAUNCH_AGENT_PIDS="$(launch_agent_pids)"')
        bootout = script.index('/bin/launchctl bootout "gui/$USER_ID/$LAUNCH_AGENT_LABEL"')
        graceful_term = script.index('kill -TERM "${OLD_AGENT_PID_ARRAY[@]}"')
        wait_failure = script.index("TERM 等待窗口内未退出")
        launchd_wait = script.index("# Wait until launchd has removed the old service record.")
        bootstrap = script.index('/bin/launchctl bootstrap "gui/$USER_ID"')

        self.assertLess(capture, bootout)
        self.assertLess(bootout, graceful_term)
        self.assertLess(graceful_term, wait_failure)
        self.assertLess(wait_failure, launchd_wait)
        self.assertLess(wait_failure, bootstrap)

    def test_start_script_does_not_force_kill_unrelated_port_listener(self):
        script = Path(__file__).resolve().parents[1].joinpath("start.command").read_text(encoding="utf-8")
        ownership_guard = script.index("is_owned_webui_pid()")
        port_scan = script.index('lsof -nP -tiTCP:"$PORT" -sTCP:LISTEN')
        force_kill = script.index("kill -9")
        self.assertLess(ownership_guard, port_scan)
        self.assertLess(port_scan, force_kill)
        self.assertIn('REMAINING_PORT_PIDS="$(/usr/sbin/lsof', script)


if __name__ == "__main__":
    unittest.main()
