#!/bin/zsh
set -e
unsetopt bg_nice 2>/dev/null || true

APP_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$APP_DIR"

PORT="18777"
VENV_DIR="$APP_DIR/mac_runtime/.venv"

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

if [ -z "$PYTHON_BIN" ] || [ ! -x "$PYTHON_BIN" ]; then
  echo "Python 3.13 was not found after installation."
  read "?Press Enter to close..."
  exit 1
fi

if [ ! -x "$VENV_DIR/bin/python" ]; then
  echo "Creating local Python virtual environment..."
  "$PYTHON_BIN" -m venv "$VENV_DIR"
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
  "$VENV_DIR/bin/pip" install \
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
  if ! "$VENV_DIR/bin/pip" install "camoufox[geoip]"; then
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
  if ! "$VENV_DIR/bin/python" - <<'PY'
from camoufox.pkgman import CamoufoxFetcher

CamoufoxFetcher().install()
PY
  then
    echo "Camoufox browser runtime installation failed."
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

# The launcher is intentionally a user service.  Unload the previous label
# before replacing its generated plist so a second click cannot create two
# Flask instances or a launch loop.
USER_ID="$(id -u)"
/bin/launchctl bootout "gui/$USER_ID/$LAUNCH_AGENT_LABEL" >/dev/null 2>&1 || true

OLD_PIDS="$(/usr/bin/pgrep -f "plus_launcher.pyc --no-browser --port $PORT" 2>/dev/null || true)"
PORT_PIDS="$(/usr/sbin/lsof -ti tcp:"$PORT" 2>/dev/null || true)"
PIDS_TO_STOP="$(printf "%s\n%s\n" "$OLD_PIDS" "$PORT_PIDS" | awk 'NF && !seen[$0]++')"
typeset -a PIDS_TO_STOP_ARRAY
PIDS_TO_STOP_ARRAY=()
if [ -n "$PIDS_TO_STOP" ]; then
  PIDS_TO_STOP_ARRAY=("${(@f)PIDS_TO_STOP}")
fi
if [ ${#PIDS_TO_STOP_ARRAY[@]} -gt 0 ]; then
  echo "Stopping previous WebUI on port $PORT..."
  kill "${PIDS_TO_STOP_ARRAY[@]}" 2>/dev/null || true
  sleep 1
  typeset -a STILL_RUNNING
  STILL_RUNNING=()
  for pid in "${PIDS_TO_STOP_ARRAY[@]}"; do
    if kill -0 "$pid" 2>/dev/null; then
      STILL_RUNNING+=("$pid")
    fi
  done
  if [ ${#STILL_RUNNING[@]} -gt 0 ]; then
    kill -9 "${STILL_RUNNING[@]}" 2>/dev/null || true
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
