#!/bin/zsh
set -e
unsetopt bg_nice 2>/dev/null || true

APP_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$APP_DIR"

PORT="18777"
VENV_DIR="$APP_DIR/mac_runtime/.venv"

# Serialize the complete prepare/build/bootstrap sequence. A second Finder or
# Terminal launch exits without racing virtualenv creation, npm output, or the
# generated LaunchAgent plist.
if [ "${GPTPHONE_LAUNCH_LOCK_HELD:-}" != "1" ]; then
  mkdir -p "$APP_DIR/data"
  LAUNCH_LOCK="$APP_DIR/data/start.command.lock"
  if ! GPTPHONE_LAUNCH_LOCK_HELD=1 /usr/bin/lockf -t 0 "$LAUNCH_LOCK" "$0" "$@"; then
    echo "Another gptPhone launcher is already preparing the WebUI."
    exit 1
  fi
  exit 0
fi

export PATH="/usr/local/bin:/opt/homebrew/bin:$PATH"

echo "gptPhone mac launcher"
echo "App dir: $APP_DIR"

mkdir -p "$APP_DIR/data" "$APP_DIR/engine"

PYTHON_BIN="$(command -v python3.13 || true)"
if [ -z "$PYTHON_BIN" ]; then
  if command -v brew >/dev/null 2>&1; then
    echo "Installing Python 3.13 with Homebrew..."
    brew install python@3.13
    PYTHON_BIN="$(command -v python3.13 || true)"
  else
    echo "Missing Python 3.13 and Homebrew was not found."
    echo "Please install Homebrew or Python 3.13, then run this command again."
    read "?Press Enter to close..."
    exit 1
  fi
fi

if [ -z "$PYTHON_BIN" ] || [ ! -x "$PYTHON_BIN" ] || ! "$PYTHON_BIN" -c 'import sys; raise SystemExit(0 if sys.version_info[:2] >= (3, 13) else 1)' >/dev/null 2>&1; then
  echo "Python 3.13 was not found after installation."
  echo "Install Python 3.13 (recommended: brew install python@3.13), then run start.command again."
  read "?Press Enter to close..."
  exit 1
fi

# A copied venv can still be executable while its interpreter points to the
# source Mac. Verify that it actually starts before reusing it.
if [ -x "$VENV_DIR/bin/python" ] && ! "$VENV_DIR/bin/python" -c 'import sys; raise SystemExit(0 if sys.version_info[:2] >= (3, 13) else 1)' >/dev/null 2>&1; then
  echo "The local Python environment is stale or cannot be opened; rebuilding it..."
  rm -rf "$VENV_DIR"
fi

if [ ! -x "$VENV_DIR/bin/python" ]; then
  echo "Creating local Python virtual environment..."
  "$PYTHON_BIN" -m venv "$VENV_DIR"
fi

if ! "$VENV_DIR/bin/python" -c 'import sys; raise SystemExit(0 if sys.version_info[:2] >= (3, 13) else 1)' >/dev/null 2>&1; then
  echo "The local Python 3.13 environment could not be started."
  echo "Remove mac_runtime/.venv and run start.command again, or install Python 3.13 first."
  read "?Press Enter to close..."
  exit 1
fi

if ! "$VENV_DIR/bin/python" - <<'PY' >/dev/null 2>&1
import cryptography
import curl_cffi
import flask
import requests
import selenium
import werkzeug
PY
then
  echo "Installing mac Python dependencies..."
  "$VENV_DIR/bin/python" -m pip install \
    flask==3.1.3 \
    werkzeug==3.1.8 \
    cryptography==46.0.5 \
    curl_cffi==0.15.0 \
    requests \
    selenium \
    rich \
    python-dotenv \
    pysocks \
    certifi \
    charset-normalizer \
    idna \
    urllib3
fi

export XDG_CACHE_HOME="$APP_DIR/data/cache"

echo "Checking Camoufox browser runtime..."
if ! "$VENV_DIR/bin/python" - <<'PY' >/dev/null 2>&1
import camoufox  # noqa: F401
PY
then
  echo "Installing Camoufox Python package..."
  if ! "$VENV_DIR/bin/python" -m pip install "camoufox[geoip]"; then
    echo "Camoufox Python package installation failed."
    read "?Press Enter to close..."
    exit 1
  fi
fi

if ! "$VENV_DIR/bin/python" - <<'PY' >/dev/null 2>&1
from camoufox.pkgman import installed_verstr
installed_verstr()
PY
then
  echo "Downloading Camoufox browser runtime (first run may take a while)..."
  if ! "$VENV_DIR/bin/python" "$APP_DIR/tools/install_camoufox_runtime.py"; then
    echo "Camoufox browser runtime installation failed."
    echo "GitHub API rate limits do not block the direct release fallback."
    echo "For an offline install, set CAMOUFOX_BROWSER_URL to a local or mirrored archive URL and rerun."
    read "?Press Enter to close..."
    exit 1
  fi
fi

if ! "$VENV_DIR/bin/python" - <<'PY' >/dev/null 2>&1
from camoufox.pkgman import installed_verstr
installed_verstr()
PY
then
  echo "Camoufox browser runtime is still unavailable after installation."
  read "?Press Enter to close..."
  exit 1
fi

if [ ! -f "$APP_DIR/node_chain.dat" ] && [ -f "$APP_DIR/external_assets/node_chain.dat" ]; then
  cp "$APP_DIR/external_assets/node_chain.dat" "$APP_DIR/node_chain.dat"
fi

if [ ! -f "$APP_DIR/engine/node_chain/real_sentinel_runner.js" ] && [ -f "$APP_DIR/node_chain.dat" ]; then
  echo "Preparing Node SentinelRunner..."
  APP_DIR_FOR_NODE="$APP_DIR" "$VENV_DIR/bin/python" - <<'PY'
import os
import shutil
import sys
from pathlib import Path

app_dir = Path(os.environ["APP_DIR_FOR_NODE"])
sys.path.insert(0, str(app_dir / "business_pyc"))
import resource_runtime

sys.frozen = True
sys.executable = str(app_dir / "plus_launcher.pyc")
node_dir = Path(resource_runtime.resolve_node_chain_dir())
engine_dir = app_dir / "engine"
target = engine_dir / "node_chain"
engine_dir.mkdir(parents=True, exist_ok=True)

if target.is_symlink() or target.exists():
    if (target / "real_sentinel_runner.js").exists():
        raise SystemExit(0)
    if target.is_symlink():
        target.unlink()
    elif target.is_dir():
        shutil.rmtree(target)
    else:
        target.unlink()

try:
    target.symlink_to(node_dir, target_is_directory=True)
except OSError:
    shutil.copytree(node_dir, target)
PY
fi

NODE_BIN="$(command -v node || true)"
CONFIGURED_NODE_BIN="${CODEX_NODE_BINARY:-}"
if [ -n "$CONFIGURED_NODE_BIN" ] && [ -x "$CONFIGURED_NODE_BIN" ]; then
  NODE_BIN="$CONFIGURED_NODE_BIN"
fi
if [ -z "$NODE_BIN" ] && command -v brew >/dev/null 2>&1; then
  echo "Installing Node.js with Homebrew..."
  brew install node
  hash -r 2>/dev/null || true
  NODE_BIN="$(command -v node || true)"
fi
if [ -n "$NODE_BIN" ]; then
  export CODEX_NODE_BINARY="$NODE_BIN"
else
  unset CODEX_NODE_BINARY
fi

NPM_BIN="$(command -v npm || true)"
if [ -z "$NPM_BIN" ] && command -v brew >/dev/null 2>&1; then
  echo "Node.js was found without npm; refreshing the command path..."
  hash -r 2>/dev/null || true
  NPM_BIN="$(command -v npm || true)"
fi
if [ -z "$NPM_BIN" ]; then
  echo "Missing npm. Node.js is required to rebuild the Vue dashboard before Flask starts."
  echo "Install Node.js, then run this command again."
  read "?Press Enter to close..."
  exit 1
fi

FRONTEND_DIR="$APP_DIR/frontend"
if [ -f "$FRONTEND_DIR/package.json" ]; then
  if [ ! -x "$FRONTEND_DIR/node_modules/.bin/vite" ]; then
    echo "Installing Vue dashboard dependencies..."
    (
      cd "$FRONTEND_DIR"
      "$NPM_BIN" ci --no-audit --no-fund
    )
  fi
  echo "Rebuilding Vue dashboard..."
  (
    cd "$FRONTEND_DIR"
    "$NPM_BIN" run build
  )
else
  echo "Missing frontend/package.json; cannot rebuild the Vue dashboard."
  read "?Press Enter to close..."
  exit 1
fi

export PYTHONPATH="$APP_DIR/mac_overrides:$APP_DIR/business_pyc"
export EMAIL_AUTH_IMPORTER_GUI_PORT="$PORT"
export XDG_CACHE_HOME="$APP_DIR/data/cache"

echo "Using fixed WebUI port: $PORT"
LAUNCH_AGENT_LABEL="com.gptphone.autophone"
LAUNCH_AGENT_DIR="$APP_DIR/data/launchagent"
LAUNCH_AGENT_PLIST="$LAUNCH_AGENT_DIR/$LAUNCH_AGENT_LABEL.plist"
LAUNCH_AGENT_OUT="$LAUNCH_AGENT_DIR/$LAUNCH_AGENT_LABEL.out.log"
LAUNCH_AGENT_ERR="$LAUNCH_AGENT_DIR/$LAUNCH_AGENT_LABEL.err.log"
mkdir -p "$LAUNCH_AGENT_DIR"

is_owned_webui_pid() {
  local pid="$1"
  local command_line
  [[ "$pid" == <-> ]] || return 1
  command_line="$(/bin/ps -p "$pid" -o command= 2>/dev/null || true)"
  [[ "$command_line" == *"$APP_DIR/plus_launcher.pyc"* ]] \
    && [[ "$command_line" == *"--port $PORT"* ]]
}

owned_webui_pids() {
  local pid
  for pid in "$@"; do
    if is_owned_webui_pid "$pid"; then
      print -r -- "$pid"
    fi
  done
}

launch_agent_pids() {
  local job_snapshot pid
  job_snapshot="$(/bin/launchctl print "gui/$USER_ID/$LAUNCH_AGENT_LABEL" 2>/dev/null || true)"
  while IFS= read -r pid; do
    if [[ "$pid" == <-> ]]; then
      print -r -- "$pid"
    fi
  done <<< "$(print -r -- "$job_snapshot" | /usr/bin/sed -nE 's/^[[:space:]]*pid = ([0-9]+).*$/\1/p')"
}

# The launcher is intentionally a user service. Capture the current job PID
# before bootout: a failed Flask worker can stop listening before launchd
# removes it, so a port-only check would let two SQLite owners overlap.
USER_ID="$(id -u)"
LAUNCH_AGENT_PIDS="$(launch_agent_pids)"
typeset -a LAUNCH_AGENT_PID_ARRAY
LAUNCH_AGENT_PID_ARRAY=()
if [ -n "$LAUNCH_AGENT_PIDS" ]; then
  LAUNCH_AGENT_PID_ARRAY=("${(@f)LAUNCH_AGENT_PIDS}")
fi
/bin/launchctl bootout "gui/$USER_ID/$LAUNCH_AGENT_LABEL" >/dev/null 2>&1 || true

# Explicitly stop the captured worker even when it no longer owns the HTTP
# listener. Only signal it after re-checking the command, which avoids
# affecting a reused PID or an unrelated process.
if [ ${#LAUNCH_AGENT_PID_ARRAY[@]} -gt 0 ]; then
  OLD_AGENT_PIDS="$(owned_webui_pids "${LAUNCH_AGENT_PID_ARRAY[@]}")"
  if [ -n "$OLD_AGENT_PIDS" ]; then
    typeset -a OLD_AGENT_PID_ARRAY
    OLD_AGENT_PID_ARRAY=("${(@f)OLD_AGENT_PIDS}")
    echo "Waiting for previous WebUI LaunchAgent process to exit..."
    kill -TERM "${OLD_AGENT_PID_ARRAY[@]}" 2>/dev/null || true
    for attempt in {1..120}; do
      if [ -z "$(owned_webui_pids "${LAUNCH_AGENT_PID_ARRAY[@]}")" ]; then
        break
      fi
      sleep 0.25
    done
    if [ -n "$(owned_webui_pids "${LAUNCH_AGENT_PID_ARRAY[@]}")" ]; then
      echo "旧 WebUI LaunchAgent 进程在 TERM 等待窗口内未退出，已停止重载以保护 Free SQLite 状态。"
      echo "请检查 $LAUNCH_AGENT_ERR，并确认旧进程已退出后重试。"
      exit 1
    fi
  fi
fi

# Wait until launchd has removed the old service record. ``bootout`` can
# return while the worker is unwinding browser and async resources.
for attempt in {1..120}; do
  if ! /bin/launchctl print "gui/$USER_ID/$LAUNCH_AGENT_LABEL" >/dev/null 2>&1; then
    break
  fi
  sleep 0.25
done
if /bin/launchctl print "gui/$USER_ID/$LAUNCH_AGENT_LABEL" >/dev/null 2>&1; then
  echo "旧 WebUI LaunchAgent 在等待窗口内未退出，已停止重载以避免重复实例。"
  echo "请检查 $LAUNCH_AGENT_ERR，并稍后重试。"
  exit 1
fi

owned_port_pids() {
  local raw pid
  raw="$(/usr/sbin/lsof -nP -tiTCP:"$PORT" -sTCP:LISTEN 2>/dev/null || true)"
  while IFS= read -r pid; do
    if is_owned_webui_pid "$pid"; then
      print -r -- "$pid"
    fi
  done <<< "$raw"
}

PORT_PIDS="$(owned_port_pids)"
typeset -a PIDS_TO_STOP_ARRAY
PIDS_TO_STOP_ARRAY=()
if [ -n "$PORT_PIDS" ]; then
  PIDS_TO_STOP_ARRAY=("${(@f)PORT_PIDS}")
fi
if [ ${#PIDS_TO_STOP_ARRAY[@]} -gt 0 ]; then
  echo "Stopping previous WebUI on port $PORT..."
  kill "${PIDS_TO_STOP_ARRAY[@]}" 2>/dev/null || true
  # Give the Python process enough time to close Camoufox contexts and its
  # event loop.  A short hard-kill window leaves pending browser tasks behind
  # and causes the next generation to report false recovery failures.
  for attempt in {1..120}; do
    if [ -z "$(owned_port_pids)" ]; then
      break
    fi
    sleep 0.25
  done
  STILL_LISTENING="$(owned_port_pids)"
  if [ -n "$STILL_LISTENING" ]; then
    typeset -a STILL_LISTENING_ARRAY
    STILL_LISTENING_ARRAY=("${(@f)STILL_LISTENING}")
    kill -9 "${STILL_LISTENING_ARRAY[@]}" 2>/dev/null || true
    for attempt in {1..40}; do
      if [ -z "$(owned_port_pids)" ]; then
        break
      fi
      sleep 0.25
    done
    if [ -n "$(owned_port_pids)" ]; then
      echo "旧 WebUI 进程未能退出，LaunchAgent 未重新加载。"
      exit 1
    fi
  fi
  REMAINING_PORT_PIDS="$(/usr/sbin/lsof -nP -tiTCP:"$PORT" -sTCP:LISTEN 2>/dev/null || true)"
  if [ -n "$REMAINING_PORT_PIDS" ]; then
    echo "Port $PORT is still occupied after stopping the gptPhone listener; LaunchAgent was not started."
    exit 1
  fi
fi

cat > "$LAUNCH_AGENT_PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>$LAUNCH_AGENT_LABEL</string>
  <key>ProgramArguments</key>
  <array>
    <string>$VENV_DIR/bin/python</string>
    <string>$APP_DIR/plus_launcher.pyc</string>
    <string>--no-browser</string>
    <string>--port</string>
    <string>$PORT</string>
  </array>
  <key>WorkingDirectory</key>
  <string>$APP_DIR</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>PYTHONPATH</key>
    <string>$APP_DIR/mac_overrides:$APP_DIR/business_pyc</string>
    <key>EMAIL_AUTH_IMPORTER_GUI_PORT</key>
    <string>$PORT</string>
    <key>XDG_CACHE_HOME</key>
    <string>$APP_DIR/data/cache</string>
    <key>CODEX_NODE_BINARY</key>
    <string>${CODEX_NODE_BINARY:-}</string>
  </dict>
  <key>ProcessType</key>
  <string>Background</string>
  <key>LSUIElement</key>
  <true/>
  <key>LimitLoadToSessionType</key>
  <string>Aqua</string>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <false/>
  <key>ThrottleInterval</key>
  <integer>10</integer>
  <key>StandardOutPath</key>
  <string>$LAUNCH_AGENT_OUT</string>
  <key>StandardErrorPath</key>
  <string>$LAUNCH_AGENT_ERR</string>
</dict>
</plist>
PLIST
touch "$LAUNCH_AGENT_OUT" "$LAUNCH_AGENT_ERR"
chmod 600 "$LAUNCH_AGENT_PLIST" "$LAUNCH_AGENT_OUT" "$LAUNCH_AGENT_ERR"

if ! /bin/launchctl bootstrap "gui/$USER_ID" "$LAUNCH_AGENT_PLIST"; then
  echo "无法加载后台服务，请检查：$LAUNCH_AGENT_ERR"
  exit 1
fi

echo "Starting background WebUI: http://127.0.0.1:$PORT"
echo "WebUI will keep running after this Terminal window closes."
ready=""
for attempt in {1..120}; do
  if /usr/bin/curl -fsS "http://127.0.0.1:$PORT/api/state" >/dev/null 2>&1; then
    ready="1"
    CACHE_BUSTER="$(date +%s)"
    if ! /usr/bin/open "http://127.0.0.1:$PORT/?v=$CACHE_BUSTER" >/dev/null 2>&1; then
      echo "WebUI is ready, but macOS could not open the browser automatically."
      echo "Open http://127.0.0.1:$PORT/ manually."
    fi
    break
  fi
  sleep 0.5
done
if [ -z "$ready" ]; then
  echo "WebUI did not become ready within 60 seconds."
  echo "Check $LAUNCH_AGENT_ERR for the background service log."
  exit 1
fi
